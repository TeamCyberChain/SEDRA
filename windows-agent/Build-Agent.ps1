param([string]$OutputDirectory = (Join-Path $PSScriptRoot 'bin'))
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if(!(Test-Path -LiteralPath $compiler)){throw 'Installed .NET Framework compiler required'}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$target=Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) 'Sedra.Agent.exe'
& $compiler /nologo /target:exe /optimize+ /platform:anycpu /out:$target /r:System.ServiceProcess.dll /r:System.Management.dll /r:System.Web.Extensions.dll /r:System.Security.dll /r:System.Xml.Linq.dll (Join-Path $PSScriptRoot 'Sedra.Agent.cs')
if($LASTEXITCODE -ne 0){throw 'Agent compilation failed'}
[pscustomobject]@{Binary=$target;SHA256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash;Authenticode=(Get-AuthenticodeSignature -LiteralPath $target).Status.ToString()}
