# Read-only trust check used by all normal-user entrances.
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ReleasePermissions.psm1') -Force
Assert-ReleaseRoot 'C:\ProgramData\LabVirtualLabReleases'
