# C52.04 (C52-04, часть «установщик»): проверка MSI агента и collector на чистой Windows (CI windows-2022).
# Без центра: тихая установка без кода — служба есть, не запущена; ошибка регистрации — откат без следов и без кода в
# журнале msiexec; обновление сохраняет регистрацию; удаление — служба и программа удалены, данные остаются;
# REMOVE_DATA=1 — данные удалены; у collector — правило брандмауэра. Сквозная регистрация с центром — стенд (C52-08).
#   powershell -File msi_check.ps1 -V1 dir\v1 -V2 dir\v2
param([Parameter(Mandatory)][string]$V1, [Parameter(Mandatory)][string]$V2)
$ErrorActionPreference = 'Stop'
$checks = New-Object System.Collections.Generic.List[string]
function Fail($m) { throw "FAIL: $m" }
function Msi($action, $file, [string[]]$props) {
  $dir = Join-Path $env:RUNNER_TEMP 'msi-logs'; New-Item -ItemType Directory -Force $dir | Out-Null
  $log = Join-Path $dir ("msi-" + [IO.Path]::GetFileNameWithoutExtension($file) + "-" + (Get-Random) + ".log")
  if (-not (Test-Path -LiteralPath $file)) { Fail "нет файла MSI: $file" }
  $argv = @($action, "`"$file`"", '/qn', '/norestart', '/l*v', "`"$log`"") + $props
  $p = Start-Process msiexec.exe -ArgumentList $argv -Wait -PassThru
  return @{ Code = $p.ExitCode; Log = $log }
}
function Tail($r) {
  if (-not (Test-Path $r.Log)) { Write-Host "  (нет журнала $($r.Log))"; return }
  # первое действие, вернувшее ошибку, и что было перед ним
  Select-String -Path $r.Log -Pattern 'Return value 3|CustomAction .* returned actual error|Error 1[0-9]{3}' -Context 12,2 | Select-Object -First 2 | ForEach-Object {
    $_.Context.PreContext + $_.Line + $_.Context.PostContext | ForEach-Object { Write-Host "  | $_" } }
}
function Svc($name) { Get-CimInstance Win32_Service -Filter "Name='$name'" }

$components = @(
  @{ Kind = 'agent'; Service = 'SurveyscanAgent'; Dir = 'Agent'; Config = 'config.json';
     Bad = @('COLLECTOR_URL=https://127.0.0.1:9', ('CENTER_FINGERPRINT=' + ('ab' * 32))) },
  @{ Kind = 'collector'; Service = 'SurveyscanCollector'; Dir = 'Collector'; Config = 'collector.json';
     Bad = @('CENTER_URL=https://127.0.0.1:9', ('CENTER_FINGERPRINT=' + ('ab' * 32))) }
)
foreach ($c in $components) {
  $name = "surveyscan-$($c.Kind)"
  # имена переменных в PowerShell без учёта регистра: $msi1/$msi2, не $v1 (затирал бы параметр -V1)
  $msi1 = @(Get-ChildItem -LiteralPath $V1 | Where-Object { $_.Name -like "${name}_*_windows_x64.msi" }).FullName
  $msi2 = @(Get-ChildItem -LiteralPath $V2 | Where-Object { $_.Name -like "${name}_*_windows_x64.msi" }).FullName
  if (@($msi1).Count -ne 1 -or @($msi2).Count -ne 1) { Fail "$name — MSI не найден однозначно: $msi1 / $msi2" }
  $exe = Join-Path $env:ProgramFiles "SurveyScan\$($c.Dir)\$name.exe"
  $data = Join-Path $env:ProgramData "SurveyScan\$($c.Kind)"
  $config = Join-Path $data $c.Config

  # 1. ошибка регистрации (нет связи с адресом) — установка откатывается, код не попадает в журнал
  $secret = 'MSI' + (Get-Random -Minimum 100000000 -Maximum 999999999) + 'CODE'
  $r = Msi '/i' $msi1 ($c.Bad + "REG_CODE=$secret")
  Write-Host "${name}: установка с недоступным адресом — код $($r.Code)"
  if ($r.Code -eq 0) { Fail "$name — установка с недоступным адресом прошла" }
  # 1603 — ошибка установки с откатом; другое (1619 и т. п.) — пакет не открылся, проверка отката недействительна
  if ($r.Code -ne 1603) { Tail $r; Fail "$name — ожидался откат (1603), получено $($r.Code)" }
  if (Svc $c.Service) { Fail "$name — служба осталась после отката" }
  if (Test-Path $exe) { Fail "$name — программа осталась после отката" }
  $leaks = Select-String -Path $r.Log -Pattern $secret -SimpleMatch
  if ($leaks) {
    # где утёк код — строки журнала с замаскированным значением (тестовый код случайный, но не печатаем и его)
    $leaks | Select-Object -First 5 | ForEach-Object { Write-Host ($_.Line.Replace($secret, '<REG_CODE>')) }
    Fail "$name — код регистрации в журнале msiexec ($(@($leaks).Count) строк)"
  }
  $checks.Add("$name MSI: failed registration rolls back (exit $($r.Code)): no service, no program files; REG_CODE hidden in the verbose msiexec log")

  # 2. тихая установка без кода — служба установлена (LocalSystem, автозапуск), не запущена
  $r = Msi '/i' $msi1 @()
  if ($r.Code -ne 0) { Tail $r; Fail "$name — установка без кода: $($r.Code)" }
  $s = Svc $c.Service
  if (-not $s) {
    Get-CimInstance Win32_Service | Where-Object { $_.Name -like 'Surveyscan*' } | ForEach-Object { Write-Host "service: $($_.Name) $($_.State) $($_.PathName)" }
    Select-String -Path $r.Log -Pattern 'InstallServices|ServiceInstall|Return value 3|Error 19|FirewallAdd|StartIfRegistered|Register' | Select-Object -First 40 | ForEach-Object { Write-Host $_.Line }
    Fail "$name — нет службы (журнал $($r.Log))"
  }
  if ($s.StartMode -ne 'Auto' -or $s.StartName -ne 'LocalSystem' -or $s.State -ne 'Stopped') { Fail "$name — служба: $($s.StartMode) $($s.StartName) $($s.State)" }
  if ($s.PathName -notlike "*$($c.Config)*") { Fail "$name — аргументы службы: $($s.PathName)" }
  & $exe start-service --name $c.Service --config $config | Out-Null
  if ((Svc $c.Service).State -ne 'Stopped') { Fail "$name — start-service запустил незарегистрированную службу" }
  if ($c.Kind -eq 'collector' -and -not (Get-NetFirewallRule -DisplayName 'SurveyScan Collector' -ErrorAction SilentlyContinue)) { Fail 'нет правила брандмауэра' }
  $checks.Add("$name MSI: silent install without a code — LocalSystem auto-start service installed but not started until registration" + $(if ($c.Kind -eq 'collector') { '; inbound firewall rule for the collector program' } else { '' }))

  # 3. обновление сохраняет регистрацию (конфигурация и состояние в ProgramData)
  New-Item -ItemType Directory -Force (Join-Path $data 'state') | Out-Null
  Set-Content -Path $config -Value '{"registered":"marker"}' -Encoding ascii
  Set-Content -Path (Join-Path $data 'state\marker') -Value 'state' -Encoding ascii
  $before = (Get-Item $exe).LastWriteTimeUtc
  $r = Msi '/i' $msi2 @()
  if ($r.Code -ne 0) { Tail $r; Fail "$name — обновление: $($r.Code) (журнал $($r.Log))" }
  $products = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -eq "SurveyScan $($c.Dir)" }
  if (@($products).Count -ne 1) { Fail "$name — после обновления продуктов: $(@($products).Count)" }
  if (-not (Select-String -Path $config -Pattern 'marker' -Quiet) -or -not (Test-Path (Join-Path $data 'state\marker'))) { Fail "$name — обновление потеряло регистрацию" }
  if (-not (Svc $c.Service)) { Fail "$name — нет службы после обновления" }
  $checks.Add("$name MSI: major upgrade replaces the product (one entry in Programs), keeps configuration and state in ProgramData, service kept")

  # 4. удаление — служба и программа удалены, данные остаются
  Stop-Service $c.Service -ErrorAction SilentlyContinue
  $r = Msi '/x' $msi2 @()
  if ($r.Code -ne 0) { Tail $r; Fail "$name — удаление: $($r.Code)" }
  if (Svc $c.Service) { Fail "$name — служба осталась после удаления" }
  if (Test-Path $exe) { Fail "$name — программа осталась после удаления" }
  if (-not (Test-Path $config)) { Fail "$name — удаление без REMOVE_DATA стёрло регистрацию" }
  if ($c.Kind -eq 'collector' -and (Get-NetFirewallRule -DisplayName 'SurveyScan Collector' -ErrorAction SilentlyContinue)) { Fail 'правило брандмауэра осталось' }

  # 5. повторная установка подхватывает регистрацию; удаление с REMOVE_DATA=1 — данные удалены
  $r = Msi '/i' $msi2 @()
  if ($r.Code -ne 0) { Tail $r; Fail "$name — повторная установка: $($r.Code)" }
  Stop-Service $c.Service -ErrorAction SilentlyContinue
  $r = Msi '/x' $msi2 @('REMOVE_DATA=1')
  if ($r.Code -ne 0) { Tail $r; Fail "$name — удаление с REMOVE_DATA: $($r.Code)" }
  if (Test-Path $data) { Fail "$name — REMOVE_DATA=1 оставил данные" }
  $checks.Add("$name MSI: uninstall removes service and program, keeps registration; REMOVE_DATA=1 removes registration, keys and queue")
}
$report = @{ package = 'C52.04'; status = 'passed'; checks = $checks; count = $checks.Count; target = 'MSI on clean Windows Server 2022 (no centre; end-to-end registration — stand C52-08)' }
$report | ConvertTo-Json -Depth 3
