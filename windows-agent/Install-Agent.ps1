param(
 [Parameter(Mandatory=$true)][string]$ConfigPath,
 [Security.SecureString]$EnrollmentKey,
 [string]$ServiceName='SEDRAAgent',
 [string]$InstallDirectory=(Join-Path $env:ProgramFiles 'SEDRA\Agent'),
 [string]$DataDirectory=(Join-Path $env:ProgramData 'SEDRA\Agent'),
 [switch]$Start
)
$ErrorActionPreference='Stop'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run this installer as Administrator; no service was installed'}
if($ServiceName -notmatch '^SEDRAAgent(?:-Test-[a-f0-9]{8})?$'){throw 'Only SEDRAAgent or a bounded test service name is accepted'}
if(Get-Service -Name $ServiceName -ErrorAction SilentlyContinue){throw 'Service already exists. Stop/review its enrollment before replacing it'}
if([Environment]::OSVersion.Version.Major -lt 10 -or [int](Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release) -lt 528040){throw 'Windows 10/11 or Server equivalent and .NET Framework 4.8+ required'}
$InstallDirectory=[IO.Path]::GetFullPath($InstallDirectory);$DataDirectory=[IO.Path]::GetFullPath($DataDirectory);$ConfigPath=(Resolve-Path -LiteralPath $ConfigPath).Path
if($InstallDirectory.Contains('"') -or $DataDirectory.Contains('"')){throw 'Invalid installation path'}
if($InstallDirectory.TrimEnd('\').Equals($DataDirectory.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase) -or $InstallDirectory.StartsWith($DataDirectory.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $DataDirectory.StartsWith($InstallDirectory.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Separate non-overlapping binary and data directories are required'}
foreach($target in @($InstallDirectory,$DataDirectory)){
 if((Test-Path -LiteralPath $target) -and @(Get-ChildItem -LiteralPath $target -Force).Count -gt 0){$marker=Join-Path $target '.sedra-agent-directory';if(!(Test-Path -LiteralPath $marker) -or [IO.File]::ReadAllText($marker).Trim() -ne $ServiceName){throw 'Refusing to change ACLs on an existing unrelated directory'}}
 $root=[IO.Path]::GetPathRoot($target);if($target.TrimEnd('\') -eq $root.TrimEnd('\')){throw 'A dedicated non-root directory is required'}
 if($target.StartsWith('\\')){throw 'Local installation directories required'}
 $part=$target;while($part){if((Test-Path -LiteralPath $part) -and ((Get-Item -LiteralPath $part).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse-point installation paths are refused'};$parent=Split-Path -Parent $part;if($parent -eq $part){break};$part=$parent}
 New-Item -ItemType Directory -Force -Path $target | Out-Null
 & icacls.exe $target /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
 if($LASTEXITCODE -ne 0){throw 'Could not protect installation directories'}
 [IO.File]::WriteAllText((Join-Path $target '.sedra-agent-directory'),$ServiceName)
}
$source=Join-Path $PSScriptRoot 'Sedra.Agent.exe';if(!(Test-Path -LiteralPath $source)){$source=Join-Path $PSScriptRoot 'bin\Sedra.Agent.exe'}
if(!(Test-Path -LiteralPath $source)){throw 'Build-Agent.ps1 must produce Sedra.Agent.exe first'}
$binary=Join-Path $InstallDirectory 'Sedra.Agent.exe';Copy-Item -LiteralPath $source -Destination $binary -Force
if(!$EnrollmentKey){$EnrollmentKey=Read-Host 'Endpoint-only enrollment credential (hidden)' -AsSecureString}
# Send the secret over stdin, never as a process command-line argument.
$psi=New-Object Diagnostics.ProcessStartInfo;$psi.FileName=$binary;$psi.Arguments='provision "'+$DataDirectory+'" "'+$ConfigPath+'"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
$process=[Diagnostics.Process]::Start($psi);$pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($EnrollmentKey)
try{$plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer);$process.StandardInput.WriteLine($plain);$process.StandardInput.Close()}finally{$plain=$null;[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)}
$process.WaitForExit();if($process.ExitCode -ne 0){throw 'Enrollment failed; no service was registered'}
$config=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
foreach($watch in @($config.watch_directories)){if(!(Test-Path -LiteralPath $watch -PathType Container)){throw 'Configured watch directory does not exist'};$watchFull=[IO.Path]::GetFullPath($watch);foreach($private in @($InstallDirectory,$DataDirectory)){if($watchFull.Equals($private,[StringComparison]::OrdinalIgnoreCase) -or $watchFull.StartsWith($private.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $private.StartsWith($watchFull.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Agent binary/data directories cannot be watched'}}}
$command='"'+$binary+'" --service "'+$DataDirectory+'" '+$ServiceName
New-Service -Name $ServiceName -BinaryPathName $command -DisplayName 'SEDRA Windows Endpoint Agent' -StartupType Automatic -Credential (New-Object Management.Automation.PSCredential('NT AUTHORITY\LocalService',(New-Object Security.SecureString))) -Description 'Explicitly scoped endpoint metadata to an enrolled SEDRA endpoint; no content or command-line capture' | Out-Null
& sc.exe sidtype $ServiceName unrestricted | Out-Null;if($LASTEXITCODE -ne 0){throw 'Service SID configuration failed; service was not started'}
& sc.exe config $ServiceName start= delayed-auto | Out-Null;if($LASTEXITCODE -ne 0){throw 'Delayed startup configuration failed'}
& sc.exe failure $ServiceName reset= 86400 actions= restart/30000/restart/60000/restart/300000 | Out-Null
if($LASTEXITCODE -ne 0){throw 'Service recovery configuration failed'}
$sid=New-Object Security.Principal.NTAccount('NT SERVICE',$ServiceName);$sid=$sid.Translate([Security.Principal.SecurityIdentifier]).Value
& icacls.exe $InstallDirectory /grant ('*'+$sid+':(OI)(CI)RX') | Out-Null;if($LASTEXITCODE -ne 0){throw 'Service binary access failed'}
& icacls.exe $DataDirectory /grant ('*'+$sid+':(OI)(CI)M') | Out-Null;if($LASTEXITCODE -ne 0){throw 'Service data access failed'}
# The administrator explicitly selects these folders. Grant metadata/list access only.
foreach($watch in @($config.watch_directories)){& icacls.exe $watch /grant ('*'+$sid+':(RD,RA,REA,RC,S)') | Out-Null;if($LASTEXITCODE -ne 0){throw 'Watch directory access failed'}}
if($Start){Start-Service -Name $ServiceName}
[pscustomobject]@{Service=$ServiceName;Account='NT AUTHORITY\LocalService';Startup='Automatic delayed';Started=[bool]$Start;Binary=$binary;DataDirectory=$DataDirectory;Authenticode=(Get-AuthenticodeSignature -LiteralPath $binary).Status.ToString()}
