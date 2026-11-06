# Teacher/admin pull from the central HTTPS publisher; explicit approval digest required.
[CmdletBinding()]
param([ValidateSet('Sync','SelectCached')][string]$Mode='Sync', [string]$ManifestUrl='',
      [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha256,
      [switch]$TestOnly)
$ErrorActionPreference='Stop'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'AdministratorRequiredForSharedStore'}
Import-Module (Join-Path $PSScriptRoot 'ReleasePermissions.psm1') -Force
$root='C:\ProgramData\LabVirtualLabReleases'
$python='C:\ProgramData\LabPlatformIO-v2\releases\pio-ststm32-20261102-v2\runtime\penv\Scripts\python.exe'
$arguments=@('-I','-B',(Join-Path $PSScriptRoot 'central_release.py'),'--root',$root,'--sha256',$ManifestSha256)
if($Mode -eq 'Sync'){
    if(-not $ManifestUrl){throw 'ManifestURLRequired'}
    $arguments+=@('--url',$ManifestUrl)
}else{
    if($ManifestUrl){throw 'CachedSelectionNeedsNoURL'}
    $arguments+='--select-cached'
}
if($TestOnly){$arguments+='--test-only'}
New-ReleaseProtectedRoot $root
& $python @arguments
if($LASTEXITCODE -ne 0){throw 'CentralSyncFailed; old available pointer retained unless the new release was fully verified'}
Assert-ReleaseTree $root
Write-Output 'CENTRAL RELEASE READY. Personal WSLs have not been updated.'
