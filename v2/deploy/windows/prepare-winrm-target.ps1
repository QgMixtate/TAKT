# SurveyScan: prepare a Windows PC for read-only remote inventory over WinRM (pilot C34, issue #10; C51.03).
# Run in Windows PowerShell 5.1 "as Administrator" on the target PC, or from a GPO immediate task as SYSTEM with -Gpo.
# Idempotent: safe to run again.
# Grants the collection account (or group) ONLY: WinRM logon, remote WMI read on root\cimv2, DCOM remote access.
# It does NOT make the account an administrator and does not change service (SCM) permissions.
#  default: groups, WMI rights, WinRM service, HTTPS listener (domain CA certificate if present, else self-signed),
#           firewall for the collector only, PUBLIC certificate file for the stand/Web form.
#  -Gpo:    groups, service, HTTP listener and firewall come from the GPO (see deploy/OPERATIONS.md, section 11);
#           the script only grants WMI rights and creates the HTTPS listener if a domain CA certificate is present.
#  -Kerberos: also prepare WinRM over HTTP 5985 with Kerberos (collection by PC name): HTTP listener, firewall 5985
#           only from the collector, Kerberos on, Basic and unencrypted traffic off (messages are Kerberos-encrypted).
param(
  [string]$Account = 'AWM\scanwinrm',   # collection account or domain group (not an admin)
  [string]$Collector = '10.170.108.2',   # only this address may connect to port 5986
  [switch]$Gpo,
  [switch]$Kerberos
)
$ErrorActionPreference = 'Stop'
$sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Host "Account $Account = $sid"

# 1. Local groups by well-known SID (works on any Windows language); with -Gpo the GPO adds them
if (-not $Gpo) {
  foreach ($g in @('S-1-5-32-580', 'S-1-5-32-562')) {   # Remote Management Users, Distributed COM Users
    $group = Get-LocalGroup -SID $g
    try { Add-LocalGroupMember -SID $g -Member $sid; Write-Host "[+] added to $($group.Name)" }
    catch [Microsoft.PowerShell.Commands.MemberExistsException] { Write-Host "[ok] already in $($group.Name)" }
  }
}

# 2. WMI namespace root\cimv2: Enable Account (0x1) + Remote Enable (0x20), inherited by sub-namespaces
# Stand report #13: Get-WmiObject -Class __SystemSecurity may return an object without methods; call the singleton
# methods by path. The descriptor is read and written in binary form (GetSD/SetSD) and edited with .NET:
# GetSecurityDescriptor resolves every trustee and fails ("Unexpected error") on a SID of a deleted account.
$wmiSec = New-Object System.Management.ManagementObject('root\cimv2:__SystemSecurity=@')
$got = $wmiSec.InvokeMethod('GetSD', $null, $null)
if ($got['ReturnValue'] -ne 0) { throw "WMI GetSD failed: $($got['ReturnValue'])" }
$bin = [byte[]]$got['SD']
$raw = [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$bin, 0)
$present = $raw.DiscretionaryAcl | Where-Object { $_.AceQualifier -eq 'AccessAllowed' -and $_.SecurityIdentifier.Value -eq $sid -and ($_.AccessMask -band 0x21) -eq 0x21 }
if ($present) { Write-Host '[ok] WMI root\cimv2 rights present' }
else {
  $ace = [System.Security.AccessControl.CommonAce]::new([System.Security.AccessControl.AceFlags]::ContainerInherit, [System.Security.AccessControl.AceQualifier]::AccessAllowed, 0x21, [System.Security.Principal.SecurityIdentifier]::new($sid), $false, $null)
  # canonical order: explicit ACEs before inherited ones
  $at = @($raw.DiscretionaryAcl | Where-Object { -not ($_.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited) }).Count
  $raw.DiscretionaryAcl.InsertAce($at, $ace)
  $out = New-Object byte[] $raw.BinaryLength
  $raw.GetBinaryForm($out, 0)
  $in = $wmiSec.GetMethodParameters('SetSD'); $in['SD'] = $out
  $r = $wmiSec.InvokeMethod('SetSD', $in, $null)
  if ($r['ReturnValue'] -ne 0) { throw "WMI SetSD failed: $($r['ReturnValue'])" }
  Write-Host '[+] WMI root\cimv2: Enable Account + Remote Enable'
}

# 3. WinRM service and permission for Remote Management Users
if (-not $Gpo) { Set-Service -Name WinRM -StartupType Automatic; Start-Service -Name WinRM }
$sddl = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
if ($sddl -match ';;;S-1-5-32-580\)' -or $sddl -match ';;;RM\)') { Write-Host '[ok] WinRM RootSDDL allows Remote Management Users' }
else { Set-Item WSMan:\localhost\Service\RootSDDL -Value ($sddl -replace '(D:P?)', '$1(A;;GXGR;;;S-1-5-32-580)') -Force; Write-Host '[+] WinRM RootSDDL: Remote Management Users' }

# 4. HTTPS listener: prefer a certificate issued by the domain CA (autoenrollment) for this PC's DNS name
$fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
$domainCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
  $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) -and $_.Issuer -ne $_.Subject -and
  ($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.1' }) -and
  ($_.DnsNameList | Where-Object { $_.Unicode -eq $fqdn })
} | Sort-Object NotAfter -Descending | Select-Object -First 1
$listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' }
$thumb = $null
if ($listener) {
  $thumb = (Get-ChildItem "$($listener.PSPath)" | Where-Object Name -eq 'CertificateThumbprint').Value
  $current = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
  # стенд №17: прежний прослушиватель на самоподписанном сертификате мешал перейти на CA домена — перепривязываем
  if ($domainCert -and $thumb -ne $domainCert.Thumbprint -and (-not $current -or $current.Issuer -eq $current.Subject)) {
    Remove-Item -Path $listener.PSPath -Recurse -Force
    New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $domainCert.Thumbprint -Force | Out-Null
    $thumb = $domainCert.Thumbprint
    Write-Host "[+] HTTPS listener on 5986 moved to the domain CA certificate for $fqdn"
  } else {
    Write-Host "[ok] HTTPS listener exists"
  }
} elseif ($domainCert) {
  New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $domainCert.Thumbprint -Force | Out-Null
  $thumb = $domainCert.Thumbprint
  Write-Host "[+] HTTPS listener on 5986 for $fqdn (domain CA certificate)"
} elseif ($Gpo) {
  Write-Host '[skip] no domain CA certificate yet: HTTPS listener not created (HTTP 5985 + Kerberos works without it)'
} else {
  $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$fqdn" -and $_.NotAfter -gt (Get-Date).AddDays(30) -and $_.HasPrivateKey } | Select-Object -First 1
  if (-not $cert) { $cert = New-SelfSignedCertificate -DnsName $fqdn, $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(3) -KeyExportPolicy NonExportable }
  New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
  $thumb = $cert.Thumbprint
  Write-Host "[+] HTTPS listener on 5986 for $fqdn (self-signed)"
}

# 4a. Kerberos over HTTP 5985 (-Kerberos): listener, service auth settings; firewall below (not in GPO mode)
if ($Kerberos) {
  if (Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTP' }) { Write-Host '[ok] HTTP listener exists' }
  else { New-Item -Path WSMan:\localhost\Listener -Transport HTTP -Address * -Force | Out-Null; Write-Host '[+] HTTP listener on 5985' }
  if ((Get-Item WSMan:\localhost\Service\Auth\Kerberos).Value -ne 'true') { Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true; Write-Host '[+] WinRM Kerberos authentication on' } else { Write-Host '[ok] WinRM Kerberos authentication on' }
  if ((Get-Item WSMan:\localhost\Service\AllowUnencrypted).Value -ne 'false') { Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false; Write-Host '[+] WinRM unencrypted traffic off' } else { Write-Host '[ok] WinRM unencrypted traffic off' }
  if ((Get-Item WSMan:\localhost\Service\Auth\Basic).Value -ne 'false') { Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false; Write-Host '[+] WinRM Basic authentication off' } else { Write-Host '[ok] WinRM Basic authentication off' }
  if (-not $Gpo) {
    if (Get-NetFirewallRule -Name 'SurveyScan-WinRM-HTTP' -ErrorAction SilentlyContinue) { Set-NetFirewallRule -Name 'SurveyScan-WinRM-HTTP' -RemoteAddress $Collector; Write-Host '[ok] firewall 5985 rule updated' }
    else { New-NetFirewallRule -Name 'SurveyScan-WinRM-HTTP' -DisplayName 'SurveyScan WinRM HTTP Kerberos (collector only)' -Direction Inbound -Protocol TCP -LocalPort 5985 -RemoteAddress $Collector -Action Allow | Out-Null; Write-Host "[+] firewall: 5985 from $Collector" }
  }
  Write-Host "Kerberos: collect by name $fqdn (SPN HTTP/$fqdn or HOST/$fqdn must exist: setspn -L $env:COMPUTERNAME)"
}

if ($Gpo) { Write-Host "DONE (GPO mode). Host: $fqdn"; exit 0 }

# 5. Firewall: port 5986 only from the collector address
if (Get-NetFirewallRule -Name 'SurveyScan-WinRM-HTTPS' -ErrorAction SilentlyContinue) { Set-NetFirewallRule -Name 'SurveyScan-WinRM-HTTPS' -RemoteAddress $Collector; Write-Host '[ok] firewall rule updated' }
else { New-NetFirewallRule -Name 'SurveyScan-WinRM-HTTPS' -DisplayName 'SurveyScan WinRM HTTPS (collector only)' -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress $Collector -Action Allow | Out-Null; Write-Host "[+] firewall: 5986 from $Collector" }

# 6. Public certificate for the stand/Web form, PEM text (no private key). Optional in the Web form: without it the
#    collector remembers the certificate on first connection.
$out = "C:\surveyscan-winrm-$($env:COMPUTERNAME).pem"
$der = (Get-Item "Cert:\LocalMachine\My\$thumb").RawData
$pem = "-----BEGIN CERTIFICATE-----`r`n" + [Convert]::ToBase64String($der, 'InsertLineBreaks') + "`r`n-----END CERTIFICATE-----`r`n"
[System.IO.File]::WriteAllText($out, $pem)
Write-Host ''
Write-Host "DONE. Host: $fqdn"
Write-Host "Certificate thumbprint (compare with the stand): $thumb"
Write-Host "Public certificate for the stand: $out"
