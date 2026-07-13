# Sources & Provenance

## Authoritative source

These documents are the **Microsoft Open Specifications** — Windows Protocols
technical documentation. Canonical home:

- Index: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-winprotlp/92b33e19-6fff-496b-86c3-d168206f9845
- Per-spec landing pages, e.g. MS-SMB2: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
- Official all-PDF bundle (~600MB) is linked from each spec's landing page.

The Open Specifications are updated frequently (MS-SMB2 alone has 80+ published
revisions). Pin to a snapshot and re-sync periodically.

## How these files were obtained

The official `MicrosoftDocs/open_specs_windows` repo hosts the content as many
small per-section markdown files with GUID filenames (not convenient for offline
use). These copies were taken from **`awakecoding/openspecs`** — a derived
compact-markdown corpus that converts the official DOCX source into one
self-contained `<SPECID>.md` per spec, optimized for `grep` and AI consumption.

- Source repo: https://github.com/awakecoding/openspecs
- Path within source: `skills/windows-protocols/<SPECID>/<SPECID>.md`
- Snapshot: cloned `master` (shallow) on the date recorded in the git log of
  this project's first commit of `specs/`.

The content is derived from the Microsoft Open Specifications and is
semantically equivalent to the published HTML/PDF; it is **not** the raw
official formatting. For a normative citation, prefer the learn.microsoft.com
landing page for the spec and section number (e.g. `MS-SMB2 §2.2.5`).

## Licensing / IP

Microsoft's Open Specifications IP notice (reproduced on each spec's landing
page) permits making copies to develop implementations of the described
technologies and distributing portions of the documentation in implementations
as needed to document them, including any included schemas, IDLs, or code
samples, with or without modification. No trade-secret rights are claimed.
Patent coverage (if any) is governed by the Microsoft Open Specifications
Promise / Community Promise — see each spec's landing page and the Patent Map.

The `awakecoding/openspecs` packaging itself carries no additional restrictions
beyond the underlying Microsoft terms.

## What's intentionally NOT included

The full corpus is 450+ specs (RDP, Exchange, Office, .NET binary protocols,
AD replication internals, etc.). Only the 28 specs relevant to an SMB file
server with pluggable authentication were curated here. Add others from the
source repo if a feature requires them.
