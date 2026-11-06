[CmdletBinding()]
param([ValidateSet('Check','Prepare','Update','Rollback','RuntimeCheck')][string]$Mode='Check',
      [Parameter(Mandatory=$true)][string]$Distro,
      [string]$ToManifestSha256='', [string]$NewProject='', [switch]$TestOnly)
$ErrorActionPreference='Stop'
$python='C:\ProgramData\LabPlatformIO-v2\releases\pio-ststm32-20261102-v2\runtime\penv\Scripts\python.exe'
$arguments=@('-I','-B',(Join-Path $PSScriptRoot 'windows_release.py'),$Mode.ToLowerInvariant(),'--distro',$Distro)
if($ToManifestSha256){$arguments+=@('--to',$ToManifestSha256)}
if($NewProject){$arguments+=@('--new-project',$NewProject)}
if($TestOnly){$arguments+='--test-only'}
& $python @arguments
exit $LASTEXITCODE
