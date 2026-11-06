# New opt-in orchestration. The frozen C-UserSetup files/hashes are not edited.
[CmdletBinding()]
param([ValidateSet('Check','Initialize')][string]$Mode='Check',
      [string]$Distro='LabWSL-Docker-TestOnly-2404-v2', [switch]$TestOnly)
$ErrorActionPreference='Stop'
$python='C:\ProgramData\LabPlatformIO-v2\releases\pio-ststm32-20261102-v2\runtime\penv\Scripts\python.exe'
$operation=if($Mode -eq 'Check'){'host-check'}else{'fresh'}
$arguments=@('-I','-B',(Join-Path $PSScriptRoot 'windows_release.py'),$operation,'--distro',$Distro)
if($TestOnly){$arguments+='--test-only'}
& $python @arguments
if($LASTEXITCODE -ne 0){throw 'Stopped; after partial fresh setup resume Manage-VirtualLab Prepare only, never rerun fresh initialization'}
Write-Output 'CHECK/SETUP PASS. Existing WSL teaching workspace setup.sh remains a separate step.'
