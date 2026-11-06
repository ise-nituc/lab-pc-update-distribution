Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Get-Digest([byte[]]$Bytes) {
    $h=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally {$h.Dispose()}
}
function Assert-Digest([string]$Value) { if($Value -cnotmatch '^[a-f0-9]{64}$'){throw 'InvalidDigest'} }
function Get-CanonicalJson($Value) {
    if($null -eq $Value){return 'null'}
    if($Value -is [array]){
        $parts=@();foreach($item in $Value){$parts+=Get-CanonicalJson $item}
        return '['+($parts -join ',')+']'
    }
    if($Value -is [pscustomobject] -or $Value -is [Collections.IDictionary]){
        $names=if($Value -is [Collections.IDictionary]){@($Value.Keys)}else{@($Value.PSObject.Properties | ForEach-Object {$_.Name})}
        $parts=@();foreach($name in ($names|Sort-Object -CaseSensitive)){
            $item=if($Value -is [Collections.IDictionary]){$Value[$name]}else{$Value.PSObject.Properties[$name].Value}
            $parts+=((ConvertTo-Json -InputObject ([string]$name) -Compress)+':'+(Get-CanonicalJson $item))
        }
        return '{'+($parts -join ',')+'}'
    }
    return (ConvertTo-Json -InputObject $Value -Compress)
}
function Convert-Record([byte[]]$Bytes) {
    if($Bytes.Length -gt 1048576){throw 'RecordTooLarge'}
    $utf=New-Object Text.UTF8Encoding($false,$true)
    return ($utf.GetString($Bytes) | ConvertFrom-Json)
}
function Assert-Keys($Record,[string[]]$Required,[string[]]$Optional=@()) {
    if($null -eq $Record -or $Record -isnot [pscustomobject]){throw 'RecordExpected'}
    $names=@($Record.PSObject.Properties | ForEach-Object {$_.Name})
    foreach($key in $Required){if($names -cnotcontains $key){throw 'MissingField'}}
    foreach($key in $names){if(($Required+$Optional) -cnotcontains $key){throw 'UnknownField'}}
}
function Assert-Plain([string]$Path) {
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor){
        if(Test-Path -LiteralPath $cursor){
            if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'LinkedPathRejected'}
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
}
function Get-SafePath([string]$Root,[string]$Name) {
    if(-not $Name -or $Name.Contains('\') -or $Name.Contains(':') -or $Name.StartsWith('/') -or $Name -match '[\x00-\x1f]'){throw 'UnsafePath'}
    foreach($part in $Name.Split('/')){
        if($part -in @('','.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part -ieq '.git' -or $part -match '^(?i:con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$'){throw 'UnsafePath'}
    }
    $path=[IO.Path]::GetFullPath((Join-Path $Root $Name.Replace('/',[IO.Path]::DirectorySeparatorChar)))
    $prefix=[IO.Path]::GetFullPath($Root).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    if(-not $path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'EscapedRoot'}
    Assert-Plain $path
    return $path
}
function Write-AtomicRecord([string]$Path,$Record) {
    Assert-Plain $Path
    $parent=Split-Path -Parent $Path
    if(-not (Test-Path -LiteralPath $parent)){[IO.Directory]::CreateDirectory($parent)|Out-Null}
    $temp=Join-Path $parent ([Guid]::NewGuid().ToString('N')+'.pending')
    $utf=New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($temp,(ConvertTo-Json -InputObject $Record -Depth 40 -Compress),$utf)
    if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temp,$Path,($temp+'.previous'))}else{[IO.File]::Move($temp,$Path)}
}
function Open-UpdateLock([string]$Path) {
    Assert-Plain $Path
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Path))|Out-Null
    try{return [IO.File]::Open($Path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch{throw 'UpdateBusy'}
}
function Assert-ProtectedTree([string]$Root,[bool]$Recurse=$true) {
    Assert-Plain $Root
    $allowed=@('S-1-5-18','S-1-5-32-544')
    $items=@((Get-Item -LiteralPath $Root -Force))
    if($Recurse){$items+=@(Get-ChildItem -LiteralPath $Root -Recurse -Force)}
    foreach($item in $items){
        Assert-Plain $item.FullName
        $acl=Get-Acl -LiteralPath $item.FullName
        $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if($allowed -notcontains $owner){throw 'UntrustedOwner'}
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
            $write=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
            if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and $allowed -notcontains $rule.IdentityReference.Value){throw 'UntrustedWriter'}
        }
    }
}
function Publish-NewSnapshotAcl([string]$Path) {
    # Only a newly extracted, hash-verified tree may receive this ACL. Never repair an existing snapshot.
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach($id in @('S-1-5-18','S-1-5-32-544','S-1-5-32-545')){
        $rights=if($id -eq 'S-1-5-32-545'){'ReadAndExecute'}else{'FullControl'}
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($id)),$rights,'ContainerInherit,ObjectInherit','None','Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    # Extraction inherited the staging ACL. Set children explicitly in this NEW tree only.
    foreach($child in Get-ChildItem -LiteralPath $Path -Recurse -Force){
        $a=Get-Acl -LiteralPath $child.FullName;$a.SetAccessRuleProtection($false,$false)
        foreach($rule in @($a.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))){$a.RemoveAccessRuleSpecific($rule)}
        $a.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        Set-Acl -LiteralPath $child.FullName -AclObject $a
    }
}
function Get-FoundationTaskPlan {
    $root='C:\ProgramData\LabUpdate'
    foreach($name in @('Acquire','ApplyShared')){
        $file=if($name -eq 'Acquire'){'Acquire.ps1'}else{'Apply-Shared.ps1'}
        [pscustomobject]@{name=$name;folder='\LabEnvironment';principal='SYSTEM';
            executable=(Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe');
            arguments=('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+(Join-Path $root ('bootstrap/'+$file))+'"');
            workingDirectory=(Join-Path $root 'bootstrap');sddl='D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;BU)'}
    }
}
function Assert-TaskSecurity([string]$Sddl) {
    $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    if($null -eq $descriptor.DiscretionaryAcl){throw 'UnprotectedTaskSecurity'}
    foreach($ace in $descriptor.DiscretionaryAcl){
        if($ace.AceType -eq [Security.AccessControl.AceType]::AccessAllowed -and
           ([long]$ace.AccessMask -band 0x500D0156) -and $ace.SecurityIdentifier.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'UntrustedTaskWriter'}
    }
}
function Assert-Channel($Channel,[bool]$AllowTestOnly,[bool]$AllowDisabled=$false) {
    Assert-Keys $Channel @('schema','sequence','releaseId','disabled','manifestUrl','manifestSha256','payloadUrl','payloadSha256','payloadSize','approvedModules')
    if($Channel.schema -isnot [int] -or $Channel.schema -ne 1 -or $Channel.sequence -isnot [int] -or $Channel.sequence -lt 1 -or $Channel.releaseId -cnotmatch '^[a-f0-9]{40}$' -or $Channel.disabled -isnot [bool]){throw 'ChannelRejected'}
    if($Channel.disabled -and -not $AllowDisabled){throw 'ChannelDisabled'}
    Assert-Digest $Channel.manifestSha256; Assert-Digest $Channel.payloadSha256
    if($Channel.payloadSize -isnot [int] -or $Channel.payloadSize -le 0 -or $Channel.payloadSize -gt 8388608){throw 'PayloadSizeRejected'}
    $approvalNames=@($Channel.approvedModules.PSObject.Properties | ForEach-Object {$_.Name})
    Assert-Keys $Channel.approvedModules @() $approvalNames
}
function Assert-Release([string]$Folder,$Manifest) {
    Assert-Keys $Manifest @('schema','releaseId','sourceCommit','api','status','files')
    if($Manifest.schema -isnot [int] -or $Manifest.api -isnot [int] -or $Manifest.schema -ne 1 -or $Manifest.api -ne 1 -or $Manifest.releaseId -cnotmatch '^[a-f0-9]{40}$' -or $Manifest.sourceCommit -cne $Manifest.releaseId -or $Manifest.status -cnotin @('Approved','TestOnly')){throw 'ReleaseSchemaRejected'}
    Assert-Plain $Folder
    $seen=@{}; $total=0; $count=0
    foreach($row in $Manifest.files.PSObject.Properties){
        $name=$row.Name; $record=$row.Value
        if($seen.ContainsKey($name)){throw 'DuplicatePath'}; $seen[$name]=$true
        Assert-Keys $record @('size','sha256'); Assert-Digest $record.sha256
        $path=Get-SafePath $Folder $name
        if($record.size -isnot [int] -or $record.size -lt 0 -or -not [IO.File]::Exists($path)){throw 'ReleaseFileMissing'}
        $raw=[IO.File]::ReadAllBytes($path)
        if($raw.Length -ne $record.size -or (Get-Digest $raw) -cne $record.sha256){throw 'ReleaseFileHashMismatch'}
        $total+=$raw.Length; $count++
    }
    if($count -gt 1500 -or $total -gt 8388608 -or -not $seen.ContainsKey('runner/Runner.psm1') -or -not $seen.ContainsKey('modules/index.json')){throw 'ReleaseLimitsRejected'}
    $actual=@(Get-ChildItem -LiteralPath $Folder -Recurse -File -Force)
    foreach($item in $actual){
        Assert-Plain $item.FullName
        $relative=$item.FullName.Substring($Folder.TrimEnd('\','/').Length+1).Replace('\','/')
        if($relative -ceq 'manifest.json'){continue}
        if(-not $seen.ContainsKey($relative)){throw 'UnexpectedReleaseFile'}
    }
    return $Manifest
}
function Assert-HttpsUri([string]$Url,[string[]]$AllowedHosts) {
    $uri=$null
    if(-not [Uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.Fragment -or $AllowedHosts -inotcontains $uri.DnsSafeHost){throw 'UnapprovedHTTPSOrigin'}
    return $uri
}
function Get-HttpsBytes([string]$Url,[int]$Limit,[string[]]$AllowedHosts) {
    for($redirect=0;$redirect -le 5;$redirect++){
        $uri=Assert-HttpsUri $Url $AllowedHosts
        $request=[Net.HttpWebRequest]::Create($uri); $request.AllowAutoRedirect=$false; $request.Timeout=30000
        $response=$request.GetResponse()
        try{
            if([int]$response.StatusCode -in @(301,302,303,307,308)){$Url=([Uri]::new($uri,$response.Headers['Location'])).AbsoluteUri;continue}
            $input=$response.GetResponseStream(); $memory=New-Object IO.MemoryStream
            try{
                $buffer=New-Object byte[] 8192
                while(($read=$input.Read($buffer,0,$buffer.Length)) -gt 0){$memory.Write($buffer,0,$read);if($memory.Length -gt $Limit){throw 'DownloadTooLarge'}}
                return ,$memory.ToArray()
            }finally{$input.Dispose();$memory.Dispose()}
        }finally{$response.Dispose()}
    }
    throw 'TooManyRedirects'
}
function Receive-ApprovedRelease([string]$Root,$Channel,[scriptblock]$Fetch,[bool]$AllowTestOnly=$false,[scriptblock]$ProtectCheck={param($p,$new) if($new){Publish-NewSnapshotAcl $p};Assert-ProtectedTree $p}) {
    # Internal composition API. Production bootstrap fixes Root/Fetch/trust and never exposes injection arguments.
    Assert-Plain $Root; Assert-Channel $Channel $AllowTestOnly $true
    $lock=Open-UpdateLock (Join-Path $Root 'control/store.lock')
    $phase='channel'
    try{
        $pointer=Join-Path $Root 'control/available.json'
        $holdPath=Join-Path $Root 'control/channel-state.json'
        if(Test-Path -LiteralPath $holdPath){
            $known=Convert-Record ([IO.File]::ReadAllBytes($holdPath))
            if($Channel.sequence -lt $known.sequence -or ($Channel.sequence -eq $known.sequence -and ($Channel.disabled -ne $known.disabled -or $Channel.manifestSha256 -cne $known.manifestSha256))){throw 'ChannelReplayRejected'}
        }
        if(Test-Path -LiteralPath $pointer){
            $old=Convert-Record ([IO.File]::ReadAllBytes($pointer))
            if($Channel.sequence -lt $old.sequence -or ($Channel.sequence -eq $old.sequence -and $Channel.manifestSha256 -cne $old.manifestSha256)){throw 'ChannelReplayRejected'}
        }
        if($Channel.disabled){
            Write-AtomicRecord $holdPath ([pscustomobject]@{schema=1;sequence=$Channel.sequence;disabled=$true;manifestSha256=$Channel.manifestSha256})
            throw 'ChannelDisabled'
        }
        $phase='manifest';$raw=[byte[]](& $Fetch $Channel.manifestUrl 1048576)
        if((Get-Digest $raw) -cne $Channel.manifestSha256){throw 'ManifestHashMismatch'}
        $manifest=Convert-Record $raw
        if($manifest.releaseId -cne $Channel.releaseId -or ($manifest.status -ceq 'TestOnly' -and -not $AllowTestOnly)){throw 'ReleaseNotApproved'}
        $target=Join-Path $Root ('releases/'+$Channel.releaseId)
        if(-not (Test-Path -LiteralPath $target)){
            $phase='payload';$zip=[byte[]](& $Fetch $Channel.payloadUrl 8388608)
            if($zip.Length -ne $Channel.payloadSize -or (Get-Digest $zip) -cne $Channel.payloadSha256){throw 'PayloadHashMismatch'}
            $pending=Join-Path $Root ('admin-staging/'+[Guid]::NewGuid().ToString('N'))
            [IO.Directory]::CreateDirectory($pending)|Out-Null
            Add-Type -AssemblyName System.IO.Compression
            $memory=New-Object IO.MemoryStream(,$zip)
            $archive=New-Object IO.Compression.ZipArchive($memory,[IO.Compression.ZipArchiveMode]::Read)
            try{
                $seen=@{}; $expanded=0
                foreach($entry in $archive.Entries){
                    $dest=Get-SafePath $pending $entry.FullName
                    if($seen.ContainsKey($entry.FullName) -or $entry.Length -gt 2097152 -or (($entry.ExternalAttributes -shr 16) -band 61440) -eq 40960){throw 'ArchiveEntryRejected'}
                    $seen[$entry.FullName]=$true; $expanded+=$entry.Length
                    if($expanded -gt 8388608 -or $seen.Count -gt 1500){throw 'ArchiveLimitsRejected'}
                    [IO.Directory]::CreateDirectory((Split-Path -Parent $dest))|Out-Null
                    $stream=$entry.Open();$file=[IO.File]::Open($dest,[IO.FileMode]::CreateNew)
                    try{$stream.CopyTo($file)}finally{$stream.Dispose();$file.Dispose()}
                }
            }finally{$archive.Dispose();$memory.Dispose()}
            [IO.File]::WriteAllBytes((Join-Path $pending 'manifest.json'),$raw)
            Assert-Release $pending $manifest|Out-Null
            $phase='new-acl'; & $ProtectCheck $pending $true
            [IO.Directory]::CreateDirectory((Split-Path -Parent $target))|Out-Null
            [IO.Directory]::Move($pending,$target)
        }
        if((Get-Digest ([IO.File]::ReadAllBytes((Join-Path $target 'manifest.json')))) -cne $Channel.manifestSha256){throw 'ExistingManifestMismatch'}
        Assert-Release $target $manifest|Out-Null
        & $ProtectCheck $target $false
        # Validate all module declarations before making their runner selectable.
        $phase='modules';Import-Module (Join-Path $target 'runner/Runner.psm1') -Force
        Get-ApprovedModules $target $Channel | Out-Null
        $phase='select';Write-AtomicRecord $pointer $Channel
        Write-AtomicRecord $holdPath ([pscustomobject]@{schema=1;sequence=$Channel.sequence;disabled=$false;manifestSha256=$Channel.manifestSha256})
        return [pscustomobject]@{status='Validated';releaseId=$manifest.releaseId;manifestSha256=$Channel.manifestSha256}
    }catch{
        $reason=if($_.Exception.Message -cmatch '^[A-Z][A-Za-z0-9]{0,63}$'){$_.Exception.Message}else{'ReleaseAcquisitionFailed'}
        Write-AtomicRecord (Join-Path $Root 'control/last-acquire-detail.json') ([pscustomobject]@{schema=1;phase=$phase;errorCode=$reason;status='Rejected';releaseId=$Channel.releaseId;timeUtc=[DateTime]::UtcNow.ToString('o')})
        throw
    }finally{$lock.Dispose()}
}
Export-ModuleMember -Function *
