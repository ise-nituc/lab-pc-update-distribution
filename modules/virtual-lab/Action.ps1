param([ValidateSet('check','plan','apply','verify','rollback')][string]$Phase,[string]$ContextPath)
$ErrorActionPreference='Stop'
try{
    $context=Get-Content -LiteralPath $ContextPath -Raw | ConvertFrom-Json
    Import-Module (Join-Path $PSScriptRoot 'Adapter.psm1') -Force
    $reply=Invoke-VirtualLabAdapter $context $Phase
    $reply|ConvertTo-Json -Depth 20 -Compress
}catch{
    # Product native logs stay local; never relay raw exception output into shared summaries.
    @{status='Failed';changed=@();retry='safe';errorCode='VirtualLabAdapterStopped'}|ConvertTo-Json -Compress
    exit 1
}
