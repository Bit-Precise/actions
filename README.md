# Bit-Precise signing workflows

Reusable release signing for repositories owned by organization ID `295183371`.
These workflows sign artifacts from the **current caller run**; they do not
compile, run installers, execute input programs, or publish releases.

| Workflow at `@v1` | `stage` | Flat artifact contents |
|---|---|---|
| `.github/workflows/windows-sign.yml` | `exe` | `.exe` files |
| `.github/workflows/windows-sign.yml` | `msi` | `.msi` files |
| `.github/workflows/macos-sign.yml` | `cli` | Mach-O CLI executables, including amd64/arm64/universal |
| `.github/workflows/macos-sign.yml` | `pkg` | flat `.pkg` installers |

Required inputs are `artifact-name` and `stage`. Optional
`signed-artifact-name` defaults to `<artifact-name>-signed`. Outputs are
`signed-artifact-name` and `signed-artifact-id`. The result contains the original
filenames, `SIGNINGINFO.json`, and final `SHA256SUMS`. Inputs must contain only
1–32 regular files, at most 512 MiB each and 2 GiB total. Archives, app bundles,
Electron apps, nested directories, links and mixed stages are unsupported.
GitHub artifact downloads do not retain Unix executable permissions: callers
must `chmod +x` downloaded CLI files before packaging them.

The caller must sign EXEs before assembling an MSI, then sign the MSI. Similarly,
sign CLI files before creating their TGZ/PKG, then sign the PKG. Preserve the
signed file bytes. CLI notarization submits an exact ZIP carrier; bare CLI files
and TGZ cannot be stapled. PKG notarization includes stapling and Gatekeeper
installation assessment. Use stapled PKGs for offline ticket verification.

Only `push` on `v*` tags and `workflow_dispatch` on `main` may sign. All PR event
types and callers outside the organization are rejected before signing jobs.
The Windows signing job alone requests `id-token: write`. Azure credentials come
from organization variables; Apple credentials are explicitly inherited from
organization secrets. No GitHub environment is used.

The Azure exact subject for the intended organization custom template
`[repository_owner_id, job_workflow_ref]` is:

```text
repository_owner_id:295183371:job_workflow_ref:Bit-Precise/actions/.github/workflows/windows-sign.yml@refs/tags/v1
```

Both reusable workflows and their supporting composite actions use this
repository's `v1` tag. Protect that tag and update it only to reviewed commits;
the major-version reference is intentionally movable, not a commit pin. Make
this private repository's actions accessible to approved repositories in the
organization. Shared scripts are downloaded through GitHub's private-action
access mechanism, without a cross-repository PAT or caller-source checkout.

Azure variable names: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
`AZURE_SUBSCRIPTION_ID`, `AZURE_SIGNING_ENDPOINT`, `AZURE_SIGNING_ACCOUNT`,
`AZURE_SIGNING_PROFILE`.

Apple variable names: `APPLE_APPLICATION_IDENTITY`, `APPLE_INSTALLER_IDENTITY`,
`APPLE_TEAM_ID`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`. Apple secret
names: `APPLE_APPLICATION_P12_BASE64`, `APPLE_APPLICATION_P12_PASSWORD`,
`APPLE_INSTALLER_P12_BASE64`, `APPLE_INSTALLER_P12_PASSWORD`,
`APPLE_NOTARY_KEY_P8_BASE64`. The `cli` stage needs the Application identity;
`pkg` needs Installer. Both need the team notarization API key. Keys are loaded
only into an ephemeral keychain/temp directory and removed before upload.

Test with `python3 -m unittest discover -s tests -v`. Tests use no cloud signing
services or real keys. Windows CI also exercises input staging and rejection of
unsigned outputs with native PowerShell. Successful tests are not evidence of
real Azure/Apple signing; provider validation requires operator configuration.
