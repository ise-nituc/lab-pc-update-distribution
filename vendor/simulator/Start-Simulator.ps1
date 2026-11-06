# Windows PowerShell 5.1; current non-elevated user. No setup or repair.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Project,
    [Parameter(Mandatory=$true)][string]$Distro,
    [ValidateSet('adc-led-v1')][string]$Profile = 'adc-led-v1',
    [switch]$TestOnly
)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use a non-elevated session' }
$python = 'C:\ProgramData\LabPlatformIO-v2\releases\pio-ststm32-20261102-v2\runtime\penv\Scripts\python.exe'
$arguments=@('-I','-B',(Join-Path $PSScriptRoot 'windows_launcher.py'),'--project',$Project,'--distro',$Distro,'--profile',$Profile)
if($TestOnly){$arguments+='--test-only'}
& $python @arguments
exit $LASTEXITCODE
