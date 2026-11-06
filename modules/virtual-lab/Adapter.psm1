Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Invoke-ProductNative([string]$Tools,[string]$Operation,$Context) {
    $config=$Context.config
    $shell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $test=if($config.testOnly){@('-TestOnly')}else{@()}
    if($Operation -in @('shared-apply','shared-rollback')){
        $args=@('-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',(Join-Path $Tools 'Sync-CentralVirtualLab.ps1'))
        if($Operation -eq 'shared-apply'){$args+=@('-ManifestUrl',$config.manifestUrl,'-ManifestSha256',$config.manifestSha256)}
        else{$args+=@('-Mode','SelectCached','-ManifestSha256',$config.rollbackSha256)}
        & $shell @args @test|Out-Null
        if($LASTEXITCODE -ne 0){throw 'SharedProductOperationFailed'}
        return [pscustomobject]@{status='Applied'}
    }
    $args=@('-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',(Join-Path $Tools 'Manage-VirtualLab.ps1'),'-Distro',$Context.distro,'-Mode',$Operation)+$test
    if($Operation -eq 'Prepare' -and $Context.fresh){
        $project=Join-Path $env:LOCALAPPDATA ('LabPlatformIO-v2/projects/virtual-lab-'+$config.manifestSha256.Substring(0,12))
        $args+=@('-NewProject',$project)
    }
    $lines=@(& $shell @args)
    if($LASTEXITCODE -ne 0){throw 'PersonalProductOperationFailed'}
    return (($lines -join "`n")|ConvertFrom-Json)
}
function Test-FreshProject($Context) {
    $project=Join-Path $env:LOCALAPPDATA ('LabPlatformIO-v2/projects/virtual-lab-'+$Context.config.manifestSha256.Substring(0,12))
    foreach($name in @('platformio.ini','src/main.c','.vscode/tasks.json')){
        if(-not [IO.File]::Exists((Join-Path $project $name))){return $false}
    }
    return $true
}
function Invoke-VirtualLabAdapter($Context,[string]$Phase,
    [scriptblock]$Native={param($t,$o,$c) Invoke-ProductNative $t $o $c},
    [scriptblock]$ReadShared={ $p='C:\ProgramData\LabVirtualLabReleases\available.json';if(Test-Path -LiteralPath $p){(Get-Content -LiteralPath $p -Raw|ConvertFrom-Json).manifest}else{''} },
    [scriptblock]$ProjectReady={param($c) Test-FreshProject $c}) {
    # Composition boundaries are injected only by tests; published Action.ps1 always uses the fixed defaults.
    $config=$Context.config
    $fields=@($config.PSObject.Properties.Name)
    if(@(Compare-Object @('manifestUrl','manifestSha256','rollbackSha256','testOnly') $fields).Count -or $config.manifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or $config.rollbackSha256 -cnotmatch '^[a-f0-9]{64}$' -or -not ([Uri]$config.manifestUrl).IsAbsoluteUri -or ([Uri]$config.manifestUrl).Scheme -cne 'https' -or $config.testOnly -isnot [bool]){throw 'ProductConfigRejected'}
    $tools=Join-Path $Context.snapshot 'vendor/simulator'
    $reply=[ordered]@{status='Unchanged';changed=@();retry='safe';errorCode=''}
    if($Context.scope -eq 'shared'){
        $current=& $ReadShared
        switch($Phase){
            check {if($current -cne $config.manifestSha256){$reply.status='NeedsUpdate'}}
            plan {$reply.status='Planned';$reply.plan=[ordered]@{target=$config.manifestSha256;old=$current}}
            apply {$null=& $Native $tools 'shared-apply' $Context;$reply.status='Applied';$reply.changed=@('SharedProductCache')}
            verify {if($current -cne $config.manifestSha256){throw 'SharedSelectionMismatch'};$reply.status='Verified'}
            rollback {$null=& $Native $tools 'shared-rollback' $Context;$reply.status='Applied';$reply.changed=@('SharedProductSelection')}
            default {throw 'ProductPhaseRejected'}
        }
    }else{
        if($Context.scope -ne 'windows-user'){throw 'ProductScopeRejected'}
        $mode=switch($Phase){check {'Check'};plan {'Check'};apply {if($Context.fresh){'Prepare'}else{'Update'}};verify {'Check'};rollback {'Rollback'};default {throw 'ProductPhaseRejected'}}
        $record=& $Native $tools $mode $Context
        switch($Phase){
            check {if($record.current -cne $config.manifestSha256 -or ($Context.fresh -and -not (& $ProjectReady $Context))){$reply.status='NeedsUpdate'}}
            plan {$reply.status='Planned';$reply.plan=[ordered]@{target=$config.manifestSha256;fresh=$Context.fresh}}
            apply {$reply.status='Applied';$reply.changed=@('PersonalProductSelection')}
            verify {if($record.current -cne $config.manifestSha256 -or ($Context.fresh -and -not (& $ProjectReady $Context))){throw 'PersonalProductSelectionMismatch'};$reply.status='Verified'}
            rollback {$reply.status='Applied';$reply.changed=@('PersonalProductSelection')}
        }
    }
    return [pscustomobject]$reply
}
Export-ModuleMember -Function Invoke-VirtualLabAdapter
