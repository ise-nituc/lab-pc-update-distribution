# Creates one NEW reviewed tools version only. No active switch, task/profile edits.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Bundle,
      [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha256)
$ErrorActionPreference='Stop'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'AdministratorRequired'}
Import-Module (Join-Path $PSScriptRoot 'ReleasePermissions.psm1') -Force
Assert-ReleasePlain $Bundle
$manifest=Join-Path $Bundle 'tools-manifest.json'
Assert-ReleasePlain $manifest
if((Get-FileHash -LiteralPath $manifest).Hash -ine $ManifestSha256){throw 'ToolsManifestMismatch'}
$record=Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
$names=@('Start-Simulator.ps1','Manage-VirtualLab.ps1','Initialize-WithVirtualLab.ps1','Install-SimulatorTools.ps1',
    'Sync-CentralVirtualLab.ps1','Check-ReleaseStore.ps1','ReleasePermissions.psm1',
    'contract.py','windows_launcher.py','wsl_runner.py','windows_release.py','wsl_release.py',
    'release_store.py','central_release.py','runtime_identity.py','tasks.template.json','virtual-lab-lock.json')
if($record.schema -ne 1 -or $record.product -cne 'lab-simulator-tools' -or
    @(Compare-Object $names @($record.files.PSObject.Properties.Name)).Count){throw 'ToolsManifestSchemaRejected'}
function Test-Tools([string]$Folder){
    Assert-ReleasePlain $Folder
    $expected=@($names)+@('tools-manifest.json')
    if(@(Compare-Object $expected @((Get-ChildItem -LiteralPath $Folder -Force).Name)).Count){throw 'ToolsFileSetMismatch'}
    foreach($name in $expected){
        $file=Join-Path $Folder $name
        Assert-ReleasePlain $file
        if(-not (Test-Path -LiteralPath $file -PathType Leaf)){throw 'ToolsFileMissing'}
        if($name -eq 'tools-manifest.json'){
            if((Get-FileHash -LiteralPath $file).Hash -ine $ManifestSha256){throw 'ToolsManifestMismatch'}
        }else{
            if((Get-FileHash -LiteralPath $file).Hash -ine $record.files.$name.sha256 -or
               (Get-Item -LiteralPath $file).Length -ne $record.files.$name.size){throw 'ToolsContentMismatch'}
        }
    }
}
Test-Tools $Bundle
$root='C:\ProgramData\LabSimulatorTools'
New-ReleaseProtectedRoot $root
$target=Join-Path $root $ManifestSha256
Assert-ReleasePlain $target
if(Test-Path -LiteralPath $target){Test-Tools $target; Assert-ReleaseTree $target; Write-Output 'TOOLS UNCHANGED'; exit 0}
$stage=Join-Path $root ('pending-'+[Guid]::NewGuid().ToString('N'))
Assert-ReleasePlain $stage
if(Get-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue){throw 'ToolsStageAlreadyExists'}
[IO.Directory]::CreateDirectory($stage) | Out-Null
foreach($name in @($names)+@('tools-manifest.json')){Copy-Item -LiteralPath (Join-Path $Bundle $name) -Destination (Join-Path $stage $name)}
Test-Tools $stage
Assert-ReleaseTree $stage
# Resolve both endpoints and constrain the complete directory move to this root.
$prefix=[IO.Path]::GetFullPath($root).TrimEnd('\')+'\'
foreach($path in @($stage,$target)){
    if(-not [IO.Path]::GetFullPath($path).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'ToolsMoveOutsideRoot'}
}
[IO.Directory]::Move($stage,$target)
Write-Output ('TOOLS READY: '+$target)
