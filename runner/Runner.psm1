Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Store.psm1') -Force
$script:Handlers=@('powershell-script/v1','wsl-script/v1')
function Get-ApprovedModules([string]$Snapshot,$Channel) {
    $manifestRaw=[IO.File]::ReadAllBytes((Join-Path $Snapshot 'manifest.json'))
    if((Get-Digest $manifestRaw) -cne $Channel.manifestSha256){throw 'ManifestHashMismatch'}
    $manifest=Convert-Record $manifestRaw
    Assert-Release $Snapshot $manifest|Out-Null
    $index=Convert-Record ([IO.File]::ReadAllBytes((Join-Path $Snapshot 'modules/index.json')))
    Assert-Keys $index @('schema','modules')
    if($index.schema -isnot [int] -or $index.schema -ne 1 -or $index.modules -isnot [array]){throw 'IndexSchemaRejected'}
    $ids=@{}; $out=@()
    foreach($row in $index.modules){
        Assert-Keys $row @('id','path','sha256','scopes')
        if($row.scopes -isnot [array]){throw 'ScopeRejected'}
        if($row.id -cnotmatch '^[a-z][a-z0-9-]{0,63}$' -or $ids.ContainsKey($row.id) -or $row.path -cne ('modules/'+$row.id+'/module.json')){throw 'ModuleIdRejected'}
        $ids[$row.id]=$true
        $path=Get-SafePath $Snapshot $row.path
        $raw=[IO.File]::ReadAllBytes($path)
        Assert-Digest $row.sha256
        if((Get-Digest $raw) -cne $row.sha256){throw 'ModuleHashMismatch'}
        $m=Convert-Record $raw
        Assert-Keys $m @('schema','id','version','scenario','requires','stages','recovery','retry','config')
        if($m.schema -isnot [int] -or $m.schema -ne 1 -or $m.stages -isnot [array] -or $m.id -cne $row.id -or $m.version -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,63}$' -or $m.scenario -cnotmatch '^U[0-9]{2}$' -or $m.retry -cnotin @('safe','resume','manual') -or $m.recovery -cnotin @('rollback','admin-repair')){throw 'ModuleSchemaRejected'}
        $grant=$Channel.approvedModules.PSObject.Properties[$m.id]
        Assert-Keys $m.requires @('runnerApi','windowsMinBuild') @('wsl')
        if($m.requires.PSObject.Properties['wsl'] -and $m.requires.wsl -isnot [bool]){throw 'ModuleCompatibilityRejected'}
        if($m.requires.runnerApi -isnot [int] -or $m.requires.runnerApi -ne 1 -or $m.requires.windowsMinBuild -isnot [int] -or $m.requires.windowsMinBuild -lt 0 -or [Environment]::OSVersion.Version.Build -lt $m.requires.windowsMinBuild){throw 'ModuleCompatibilityRejected'}
        if($null -eq $grant){throw 'ModuleNotApproved'}
        if($grant.Value -isnot [array]){throw 'ScopeRejected'}
        $stages=@{}; $done=@{}
        foreach($s in $m.stages){
            Assert-Keys $s @('id','scope','handler','dependsOn','timeoutSeconds','actions')
            if($s.id -cnotmatch '^[a-z][a-z0-9-]{0,63}$' -or $stages.ContainsKey($s.id)){throw 'StageIdRejected'}
            $stages[$s.id]=$true
            if($s.scope -cnotin @('shared','windows-user','wsl-user','wsl-root') -or @($grant.Value) -cnotcontains $s.scope -or @($row.scopes) -cnotcontains $s.scope){throw 'ScopeRejected'}
            if($script:Handlers -cnotcontains $s.handler -or ($s.scope -eq 'shared' -and $s.handler -ne 'powershell-script/v1') -or ($s.scope -like 'wsl-*' -and $s.handler -ne 'wsl-script/v1') -or ($s.scope -eq 'windows-user' -and $s.handler -ne 'powershell-script/v1')){throw 'UnsupportedHandler'}
            if($s.timeoutSeconds -isnot [int] -or $s.timeoutSeconds -lt 1 -or $s.timeoutSeconds -gt 1800){throw 'TimeoutRejected'}
            if($s.dependsOn -isnot [array]){throw 'StageDependencyRejected'}
            foreach($dep in $s.dependsOn){if(-not $done.ContainsKey($dep)){throw 'StageDependencyRejected'}}
            $done[$s.id]=$true
            Assert-Keys $s.actions @('check','plan','apply','verify') @('rollback')
            foreach($a in $s.actions.PSObject.Properties){
                Assert-Keys $a.Value @('entry','sha256'); Assert-Digest $a.Value.sha256
                $entry=Get-SafePath (Split-Path -Parent $path) $a.Value.entry
                if(($s.handler -eq 'powershell-script/v1' -and -not $entry.EndsWith('.ps1')) -or ($s.handler -eq 'wsl-script/v1' -and -not $entry.EndsWith('.py'))){throw 'EntryTypeRejected'}
                if((Get-Digest ([IO.File]::ReadAllBytes($entry))) -cne $a.Value.sha256){throw 'EntryHashMismatch'}
            }
            if($m.recovery -eq 'rollback' -and -not $s.actions.PSObject.Properties['rollback']){throw 'RollbackDeclarationRejected'}
        }
        if($stages.Count -eq 0){throw 'StagesRequired'}
        $out+= [pscustomobject]@{module=$m;path=$path;digest=$row.sha256}
    }
    foreach($key in $Channel.approvedModules.PSObject.Properties.Name){if(-not $ids.ContainsKey($key)){throw 'UnknownApproval'}}
    return $out
}
function Invoke-Handler($Stage,[string]$Entry,[string]$Phase,$Context,[string]$ContextPath) {
    if((Get-Digest ([IO.File]::ReadAllBytes($Entry))) -cne $Stage.actions.PSObject.Properties[$Phase].Value.sha256){throw 'EntryHashMismatch'}
    Write-AtomicRecord $ContextPath $Context
    $psi=New-Object Diagnostics.ProcessStartInfo
    $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    if($Stage.handler -eq 'powershell-script/v1'){
        $psi.FileName=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
        foreach($arg in @($Entry,$ContextPath)){if($arg.Contains('"') -or $arg -match '[\r\n]'){throw 'NativeArgumentRejected'}}
        $psi.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$Entry+'" -Phase '+$Phase+' -ContextPath "'+$ContextPath+'"'
    }else{
        if(-not $Context.distro -or $Context.distro -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$'){throw 'DistroRequired'}
        $psi.FileName=Join-Path $env:SystemRoot 'System32/wsl.exe'
        $token=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Context -Depth 30 -Compress)))
        # wslpath converts only the approved entry path; no shell interpolation.
        $entryToken=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Entry))
        $boot="import base64,json,os,runpy,subprocess,sys; c=json.loads(base64.b64decode(sys.argv[3])); ((os.geteuid()==0)==(c['scope']=='wsl-root')) or sys.exit('WSLScopeMismatch'); p=subprocess.check_output(['wslpath','-u',base64.b64decode(sys.argv[1]).decode()],text=True).strip(); sys.argv=[p,sys.argv[2],sys.argv[3]]; runpy.run_path(p,run_name='__main__')"
        $user=if($Stage.scope -eq 'wsl-root'){'root'}else{''}
        $psi.Arguments='--distribution '+$Context.distro+' '+$(if($user){'--user root '}else{''})+'--exec /usr/bin/python3 -I -B -c "'+$boot+'" '+$entryToken+' '+$Phase+' '+$token
    }
    $process=New-Object Diagnostics.Process;$process.StartInfo=$psi
    try{
        if(-not $process.Start()){throw 'HandlerStartFailed'}
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit([int]$Stage.timeoutSeconds*1000)){try{$process.Kill()}catch{};throw 'HandlerTimeout'}
        $raw=$stdout.Result
        if($raw.Length -gt 1048576){throw 'HandlerReplyTooLarge'}
        $reply=Convert-Record ([Text.Encoding]::UTF8.GetBytes($raw))
        Assert-Keys $reply @('status','changed','retry','errorCode') @('plan','changeExtent')
        if($process.ExitCode -ne 0 -or $reply.status -in @('Failed','NeedsAdminRepair')){
            $handlerFailure=New-Object InvalidOperationException ('ModuleFailure:'+ $reply.errorCode)
            $handlerFailure.Data['changed']=@($reply.changed)
            if($reply.PSObject.Properties['changeExtent']){$handlerFailure.Data['changeExtent']=$reply.changeExtent}
            throw $handlerFailure
        }
        return $reply
    }finally{$process.Dispose()}
}
function Invoke-ModulePipeline([string]$Snapshot,$Channel,[ValidateSet('Shared','User')][string]$Authority,
    [ValidateSet('Check','Plan','Apply','Verify','Rollback')][string]$Mode,[string]$StateRoot,[string]$SharedRoot,
    [string]$Distro='', [bool]$Fresh=$false,[scriptblock]$Execute={param($s,$e,$p,$c,$f) Invoke-Handler $s $e $p $c $f},$ApprovedPlans=$null) {
    # Internal composition API; production entry validates authority, protected snapshot, own distro and fixed roots.
    $modules=@(Get-ApprovedModules $Snapshot $Channel)
    Assert-Plain $StateRoot; Assert-Plain $SharedRoot
    $lock=Open-UpdateLock (Join-Path $StateRoot 'runner.lock')
    $records=@();$result=$null
    try{
        foreach($descriptor in $modules){
            $m=$descriptor.module
            foreach($stage in $m.stages){
                if(($Authority -eq 'Shared') -ne ($stage.scope -eq 'shared')){continue}
                $job=[Guid]::NewGuid().ToString('N'); $phase='check';$started=$false;$changed=@()
                $receipt=Join-Path $StateRoot ($m.id+'.'+$stage.id+'.json')
                $previous=if(Test-Path -LiteralPath $receipt){Convert-Record ([IO.File]::ReadAllBytes($receipt))}else{$null}
                $context=[pscustomobject]@{schema=1;jobId=$job;releaseId=$Channel.releaseId;moduleId=$m.id;moduleVersion=$m.version;stageId=$stage.id;
                    scope=$stage.scope;snapshot=$Snapshot;moduleRoot=(Split-Path -Parent $descriptor.path);stateRoot=$StateRoot;sharedRoot=$SharedRoot;
                    distro=$Distro;fresh=$Fresh;config=$m.config;previous=$previous}
                if($Mode -eq 'Rollback' -and -not $stage.actions.PSObject.Properties['rollback']){
                    $unsupported=[pscustomobject]@{schema=1;jobId=$job;releaseId=$Channel.releaseId;moduleId=$m.id;moduleVersion=$m.version;stage=$stage.id;
                        phase='capability';status='NotSupported';errorCode='RollbackNotSupported';changed=@();retry=$m.retry;timeUtc=[DateTime]::UtcNow.ToString('o')}
                    Write-AtomicRecord (Join-Path $StateRoot ($job+'.result.json')) $unsupported
                    $records+=$unsupported
                    continue
                }
                try{
                    if($previous -and $previous.status -eq 'NeedsAdminRepair' -and $m.retry -eq 'manual' -and $Mode -notin @('Check','Verify')){throw 'ManualRepairRequired'}
                    foreach($dep in $stage.dependsOn){
                        $depStage=@($m.stages | Where-Object {$_.id -ceq $dep})[0]
                        $depRoot=if($depStage.scope -eq 'shared'){$SharedRoot}else{$StateRoot}
                        $depPath=Join-Path $depRoot ($m.id+'.'+$dep+'.json')
                        if(-not (Test-Path -LiteralPath $depPath)){throw 'StageDependencyNotReady'}
                        $depRecord=Convert-Record ([IO.File]::ReadAllBytes($depPath))
                        if($depRecord.releaseId -cne $Channel.releaseId -or $depRecord.status -cnotin @('Validated','Unchanged')){throw 'StageDependencyNotReady'}
                    }
                    $run={param($p)
                        $action=$stage.actions.PSObject.Properties[$p]
                        if($null -eq $action){throw 'NotSupported'}
                        $entry=Get-SafePath (Split-Path -Parent $descriptor.path) $action.Value.entry
                        if((Get-Digest ([IO.File]::ReadAllBytes($entry))) -cne $action.Value.sha256){throw 'EntryHashMismatch'}
                        & $Execute $stage $entry $p $context (Join-Path $StateRoot ($job+'.context.json'))
                    }
                    if($Mode -eq 'Rollback'){$phase='rollback';$started=$true;$reply=& $run 'rollback';$status='RolledBack'}
                    elseif($Mode -eq 'Verify'){$phase='verify';$reply=& $run 'verify';if($reply.status -ne 'Verified'){throw 'VerificationRejected'};$status='Validated'}
                    else{
                        $reply=& $run 'check'
                        if($reply.status -cnotin @('NeedsUpdate','Unchanged')){throw 'CheckReplyRejected'}
                        if($reply.status -eq 'Unchanged'){
                            if($Mode -eq 'Apply'){$phase='verify';$reply=& $run 'verify';if($reply.status -ne 'Verified'){throw 'VerificationRejected'}}
                            $status='Unchanged'
                        }
                        elseif($Mode -eq 'Check'){$status='NeedsUpdate'}
                        else{
                            $phase='plan';$reply=& $run 'plan'
                            if($reply.status -ne 'Planned'){throw 'PlanReplyRejected'}
                            $context|Add-Member -NotePropertyName plan -NotePropertyValue $reply.plan -Force
                            if($Mode -eq 'Plan'){$status='Planned'}
                            else{
                                if($null -ne $ApprovedPlans){
                                    $approved=@($ApprovedPlans|Where-Object{$_.moduleId -ceq $m.id -and $_.stage -ceq $stage.id -and $_.releaseId -ceq $Channel.releaseId -and $_.status -ceq 'Planned'})
                                    if($approved.Count -ne 1 -or (Get-CanonicalJson $approved[0].plan) -cne (Get-CanonicalJson $reply.plan)){throw 'PlanChanged'}
                                }
                                $phase='apply';$started=$true;$reply=& $run 'apply'
                                if($reply.status -notin @('Applied','Unchanged')){throw 'ApplyReplyRejected'}
                                $changed=@($reply.changed)
                                $phase='verify';$reply=& $run 'verify'
                                if($reply.status -ne 'Verified'){throw 'VerificationRejected'}
                                $status='Validated'
                            }
                        }
                    }
                    $result=[pscustomobject]@{schema=1;jobId=$job;releaseId=$Channel.releaseId;moduleId=$m.id;moduleVersion=$m.version;stage=$stage.id;
                        phase=$phase;status=$status;errorCode='';changed=$changed;retry=$m.retry;timeUtc=[DateTime]::UtcNow.ToString('o')}
                    if($status -eq 'Planned'){$result|Add-Member -NotePropertyName plan -NotePropertyValue $reply.plan}
                }catch{
                    if($_.Exception.Data.Contains('changed')){
                        $reported=@($_.Exception.Data['changed'])
                        if($reported.Count -gt 0){$changed=$reported}
                    }
                    $reason=[string]$_.Exception.Message
                    $known=@('ManualRepairRequired','StageDependencyNotReady','NotSupported','EntryHashMismatch','HandlerTimeout','CheckReplyRejected','PlanReplyRejected','VerificationRejected','ApplyReplyRejected','PlanChanged')
                    if($reason -notin $known -and $reason -cnotmatch '^ModuleFailure:[A-Za-z][A-Za-z0-9]{0,63}$'){$reason='ModuleExecutionFailed'}
                    $result=[pscustomobject]@{schema=1;jobId=$job;releaseId=$Channel.releaseId;moduleId=$m.id;moduleVersion=$m.version;stage=$stage.id;
                        phase=$phase;status=$(if($started -or $phase -eq 'verify' -or $reason -eq 'ManualRepairRequired'){'NeedsAdminRepair'}else{'Rejected'});errorCode=$reason;
                        changed=$changed;retry=$m.retry;changeExtent=$(if($started -and -not $changed.Count){'UnknownPartial'}elseif($changed.Count){'DeclaredByModule'}else{'None'});timeUtc=[DateTime]::UtcNow.ToString('o')}
                    if($_.Exception.Data.Contains('changeExtent')){$result.changeExtent=[string]$_.Exception.Data['changeExtent']}
                }
                Write-AtomicRecord (Join-Path $StateRoot ($job+'.result.json')) $result
                # Check/Plan must not overwrite an applied/failed receipt.
                if($Mode -in @('Apply','Verify','Rollback')){Write-AtomicRecord $receipt $result}
                $records+=$result
                if($result.status -in @('Rejected','NeedsAdminRepair')){return ,$records}
            }
        }
        return ,$records
    }finally{$lock.Dispose()}
}
Export-ModuleMember -Function Get-ApprovedModules,Invoke-ModulePipeline,Invoke-Handler
