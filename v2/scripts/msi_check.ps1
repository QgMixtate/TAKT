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
  $log = Join-Path $env:RUNNER_TEMP ("msi-" + [IO.Path]::GetFileNameWithoutExtension($file) + "-" + (Get-Random) + ".log")
  $args = @($action, "`"$file`"", '/qn', '/norestart', '/l*v', "`"$log`"") + $props
  $p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
  return @{ Code = $p.ExitCode; Log = $log }
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
  $v1 = (Get-ChildItem $V1 -Filter "$name*_windows_x64.msi").FullName
  $v2 = (Get-ChildItem $V2 -Filter "$name*_windows_x64.msi").FullName
  $exe = Join-Path $env:ProgramFiles "SurveyScan\$($c.Dir)\$name.exe"
  $data = Join-Path $env:ProgramData "SurveyScan\$($c.Kind)"
  $config = Join-Path $data $c.Config

  # 1. ошибка регистрации (нет связи с адресом) — установка откатывается, код не попадает в журнал
  $secret = 'MSI' + (Get-Random -Minimum 100000000 -Maximum 999999999) + 'CODE'
  $r = Msi '/i' $v1 ($c.Bad + "REG_CODE=$secret")
  if ($r.Code -eq 0) { Fail "$name — установка с недоступным адресом прошла" }
  if (Svc $c.Service) { Fail "$name — служба осталась после отката" }
  if (Test-Path $exe) { Fail "$name — программа осталась после отката" }
  if (Select-String -Path $r.Log -Pattern $secret -SimpleMatch -Quiet) { Fail "$name — код регистрации в журнале msiexec" }
  $checks.Add("$name MSI: failed registration rolls back (exit $($r.Code)): no service, no program files; REG_CODE hidden in the verbose msiexec log")

  # 2. тихая установка без кода — служба установлена (LocalSystem, автозапуск), не запущена
  $r = Msi '/i' $v1 @()
  if ($r.Code -ne 0) { Fail "$name — установка без кода: $($r.Code)" }
  $s = Svc $c.Service
  if (-not $s) { Fail "$name — нет службы" }
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
  $r = Msi '/i' $v2 @()
  if ($r.Code -ne 0) { Fail "$name — обновление: $($r.Code) (журнал $($r.Log))" }
  $products = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -eq "SurveyScan $($c.Dir)" }
  if (@($products).Count -ne 1) { Fail "$name — после обновления продуктов: $(@($products).Count)" }
  if (-not (Select-String -Path $config -Pattern 'marker' -Quiet) -or -not (Test-Path (Join-Path $data 'state\marker'))) { Fail "$name — обновление потеряло регистрацию" }
  if (-not (Svc $c.Service)) { Fail "$name — нет службы после обновления" }
  $checks.Add("$name MSI: major upgrade replaces the product (one entry in Programs), keeps configuration and state in ProgramData, service kept")

  # 4. удаление — служба и программа удалены, данные остаются
  Stop-Service $c.Service -ErrorAction SilentlyContinue
  $r = Msi '/x' $v2 @()
  if ($r.Code -ne 0) { Fail "$name — удаление: $($r.Code)" }
  if (Svc $c.Service) { Fail "$name — служба осталась после удаления" }
  if (Test-Path $exe) { Fail "$name — программа осталась после удаления" }
  if (-not (Test-Path $config)) { Fail "$name — удаление без REMOVE_DATA стёрло регистрацию" }
  if ($c.Kind -eq 'collector' -and (Get-NetFirewallRule -DisplayName 'SurveyScan Collector' -ErrorAction SilentlyContinue)) { Fail 'правило брандмауэра осталось' }

  # 5. повторная установка подхватывает регистрацию; удаление с REMOVE_DATA=1 — данные удалены
  $r = Msi '/i' $v2 @()
  if ($r.Code -ne 0) { Fail "$name — повторная установка: $($r.Code)" }
  Stop-Service $c.Service -ErrorAction SilentlyContinue
  $r = Msi '/x' $v2 @('REMOVE_DATA=1')
  if ($r.Code -ne 0) { Fail "$name — удаление с REMOVE_DATA: $($r.Code)" }
  if (Test-Path $data) { Fail "$name — REMOVE_DATA=1 оставил данные" }
  $checks.Add("$name MSI: uninstall removes service and program, keeps registration; REMOVE_DATA=1 removes registration, keys and queue")
}
$report = @{ package = 'C52.04'; status = 'passed'; checks = $checks; count = $checks.Count; target = 'MSI on clean Windows Server 2022 (no centre; end-to-end registration — stand C52-08)' }
$report | ConvertTo-Json -Depth 3
