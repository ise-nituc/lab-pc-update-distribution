# Windows PowerShell 5.1. Fixed new root only; never repair an existing ACL.
Set-StrictMode -Version Latest
function Assert-ReleasePlain([string]$Path) {
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor){
        $item=Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'ReleasePathLinked'}
        $parent=Split-Path -Parent $cursor
        if($parent -eq $cursor){break}; $cursor=$parent
    }
}
function Assert-ReleaseProtected([string]$Path) {
    Assert-ReleasePlain $Path
    $acl=Get-Acl -LiteralPath $Path
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if($owner -notin @('S-1-5-18','S-1-5-32-544')){throw 'ReleaseOwnerRejected'}
    $write=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and
            $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'ReleaseWriteAccessRejected'}
    }
}
function Assert-ReleaseTree([string]$Root){
    Assert-ReleaseProtected $Root
    foreach($item in Get-ChildItem -LiteralPath $Root -Force){
        Assert-ReleaseProtected $item.FullName
        if($item.PSIsContainer){Assert-ReleaseTree $item.FullName}
    }
}
function Assert-ReleaseRoot([string]$Root){
    if($Root -cnotin @('C:\ProgramData\LabVirtualLabReleases','C:\ProgramData\LabSimulatorTools')){throw 'UnexpectedReleaseRoot'}
    Assert-ReleaseTree $Root
    $marker=Get-Content -LiteralPath (Join-Path $Root 'root.json') -Raw | ConvertFrom-Json
    if($marker.schema -ne 1 -or $marker.purpose -cne (Split-Path -Leaf $Root)){throw 'UnmanagedExistingSharedRoot'}
}
function New-ReleaseProtectedRoot([string]$Root){
    if($Root -cnotin @('C:\ProgramData\LabVirtualLabReleases','C:\ProgramData\LabSimulatorTools')){throw 'UnexpectedReleaseRoot'}
    Assert-ReleasePlain $Root
    if(Get-Item -LiteralPath $Root -Force -ErrorAction SilentlyContinue){Assert-ReleaseRoot $Root; return}
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.SetOwner($admins)
    foreach($sid in @('S-1-5-18','S-1-5-32-544','S-1-5-32-545')){
        $identity=New-Object Security.Principal.SecurityIdentifier($sid)
        $rights=if($sid -eq 'S-1-5-32-545'){'ReadAndExecute'}else{'FullControl'}
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,$rights,'ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    # Create with the final protected ACL, rather than exposing a writable window.
    [IO.Directory]::CreateDirectory($Root,$acl) | Out-Null
    $marker=@{schema=1;purpose=(Split-Path -Leaf $Root)} | ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $Root 'root.json'),$marker,(New-Object Text.UTF8Encoding($false)))
    Assert-ReleaseRoot $Root
}
Export-ModuleMember -Function Assert-ReleasePlain,Assert-ReleaseProtected,Assert-ReleaseTree,Assert-ReleaseRoot,New-ReleaseProtectedRoot
