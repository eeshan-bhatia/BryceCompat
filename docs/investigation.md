# Original media investigation

Evidence labels: CONFIRMED means observed here; LIKELY is a hypothesis;
UNKNOWN means insufficient evidence; NOT TESTED means the experiment was not run.

## Bryce 4

- CONFIRMED: user supplied `bryce4/Bryce_4.iso`, 529,401,856 bytes, SHA-256
  `fe6f6f4a3ee1bd83fe90f181211abd677496b22bd2c8397186fb1e2a331de8d4`.
  7-Zip 22.01 lists its ISO filesystem. It reports 311,296 trailing bytes;
  their meaning is UNKNOWN. The listing has duplicate asset paths; do not
  flatten/extract the whole disc and assume duplicates are interchangeable.
- CONFIRMED: root `Setup.exe`, 71,680 bytes, SHA-256
  `a6d2f8b9173fd43f03aabff0b8cc3fadbd0b15224bcbe5f562a32158a297b502`,
  is PE32/x86, GUI subsystem, fixed file version `5.50.137.0`.
  Its version strings identify InstallShield and a 32-bit setup launcher.
  This bootstrapper is not NE/16-bit. That does not classify all child components.
- CONFIRMED static imports: VERSION.dll, KERNEL32.dll, USER32.dll, GDI32.dll.
  Names/functions and resource identities are in the local JSON inventory.
  No missing dependency has been demonstrated. `_ISDel.exe` and `_Setup.dll`
  are also PE32/x86. `_INST32I.EX_` remains unclassified/compressed data.
- CONFIRMED: `SETUP.INI` names Bryce 4.0. Disc root has `data1.cab`, `data1.hdr`,
  `_sys1.cab/.hdr`, `_user1.cab/.hdr`, `setup.ins`, `_SETUP.LIB`, `data.1`,
  and supplemental layout/language data. `data1.cab` starts with `49 53 63 28`
  rather than Microsoft CAB magic. 7-Zip failed to open it as CAB.
  LIKELY: InstallShield-specific package format; exact extraction support remains
  unverified. A compatible read-only package inspector is the next static step.
- Original application executable: UNKNOWN; not exposed as a root Bryce EXE in
  the inspected ISO listing. Payload extraction and registration are unresolved.
- Installer running without a window: user-reported investigation target;
  NOT TESTED here. No root cause is confirmed.
- CONFIRMED: readme discusses a separate Content CD; this image also includes
  model/texture libraries, sample scenes, documentation, QuickTime30.exe,
  Acrobat Reader and optional-looking exporters. Presence alone does not prove
  runtime necessity. Application installation completeness is UNKNOWN until
  package inspection/install testing; optional second-disc coverage is UNKNOWN.
- HFS/hybrid layout: UNKNOWN; only ISO view inspected, no Mac resource executed.
- Evidence: ignored `reports/bryce4-iso-listing.txt` and
  `reports/bryce4-installer-inventory.json`; selected root files were extracted
  read-only from the ISO into ignored `extracted-media/bryce4-install` using
  exact filenames and no overwrite. This subset is not a deployable installation.
  A path-sanitized static inventory is retained in
  `docs/evidence/bryce4-installer-inventory.json`; it contains metadata, not binaries.
- Next runtime experiment, requiring explicit user consent: mount the original
  image and run its root Setup.exe with full media available. Observe process
  descendants, visible/hidden windows, rectangles, and exit status. No guessed
  compatibility flags should be applied before reproducing the failure.

## Bryce 3D

- Media analyzed: none so far. Initial bounded searches found no Bryce 3D media
  under `D:\Coding`, Downloads, or common Program Files locations.
- Application/installer identity, architectures, dependencies: UNKNOWN.
- Installation and application functionality: NOT TESTED.
- No shared compatibility settings inferred from Bryce 4.
- Next experiment: separately inventory the Windows side of original media;
  identify installer, application, package data, and optional content.

## What the tools establish

Static format detection and a hash establish file properties, not whether Bryce
works. Import names do not prove runtime graphics API usage or missing DLLs.
Process creation, a responsive WM_NULL probe, and visible windows are separate
observations; none is a scene-editing or rendering test.

The user downloaded the Bryce 4 archive. The agent did not download proprietary
media. No original media was mounted, executed, or redistributed during these
static checks.

Binary parsing follows Microsoft's [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
JSON uses [nlohmann/json v3.12.0](https://github.com/nlohmann/json/releases/tag/v3.12.0)
(MIT), vendored with its license. Header SHA-256:
`aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63`.
