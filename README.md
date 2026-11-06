# Lab PC update distribution

This bundle contains management source, module definitions and instructions only.
It contains no private Git history, credentials, Windows images, WSL archives,
VSIX packages or third-party program binaries. Publishing and endpoint adoption
are separate approvals. The accompanying private review report is not an asset
to upload. Exported self-authored code is provided under the MIT License in
docs/LICENSE.txt. Product releases and third-party packages retain their own terms.

The fixed Windows PowerShell bootstrap verifies an approved HTTPS channel,
release and exact file hashes before selecting an immutable snapshot. Two fixed
tasks acquire shared definitions and apply approved shared module stages.
Personal stages run as the current Windows/WSL owner; Linux root stages are
explicit. WSL owners can already choose Linux root: this is not a sandbox.

Modules declare check/plan/apply/verify, handler API, required scopes and recovery
policy. IDs are not hardcoded. Adding a reviewed module and its index/approval to
a new release does not change task actions, ACLs or bootstrap files. Rollback is
optional. Partial failures are recorded as NeedsAdminRepair; no automatic WSL
reimport or deletion of student work is performed.

Initial modules:

- Virtual Lab: adapter to the existing product cache and personal update/rollback
  implementation. TestOnly R0/R1 selection is not a general deployment approval.
- WSL APT: Ubuntu 24.04, exact package versions, approved origins and dependency
  transitions. Module 0.1.1 pins make 4.3-4.1build2 from Ubuntu noble/main amd64
  for no-op acceptance, with no approved package changes. A different installed
  version requiring changes is rejected. Real upgrade acceptance remains pending.

A bootstrap install, real task/NTFS acceptance, real product GUI and real APT
application require a separate endpoint-specific approval. The initial release
is TestOnly. Publishing a release does not authorize endpoint adoption or fleet
deployment. No private GitHub token is required on endpoints. Windows/WSL images,
APT packages and product binary assets are not redistributed in this bundle.
