param([string]$ServiceName='SEDRAAgent',[string]$InstallDirectory=(Join-Path $env:ProgramFiles 'SEDRA\Agent'))
$ErrorActionPreference='Stop'
if($ServiceName -notmatch '^SEDRAAgent(?:-Test-[a-f0-9]{8})?$'){throw 'Refusing unrelated service name'}
$service=Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if(!$service){throw 'Service not found'}
$expected='"'+(Join-Path ([IO.Path]::GetFullPath($InstallDirectory)) 'Sedra.Agent.exe')+'" --service '
if(!$service.PathName.StartsWith($expected,[StringComparison]::OrdinalIgnoreCase)){throw 'Service executable path does not match this installation'}
Stop-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
& sc.exe delete $ServiceName | Out-Null;if($LASTEXITCODE -ne 0){throw 'Service removal failed'}
Write-Output 'SEDRA service removed. Data, encrypted enrollment, binaries and explicitly granted folder ACLs are retained for reviewed cleanup.'
