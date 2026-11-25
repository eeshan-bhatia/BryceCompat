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
  are also PE32/x86. Deark decoded `_INST32I.EX_`: INSTALL.EXE, zdata.dll and
  WUTL95i.DLL are PE32/x86; BOOT16.EXE is NE. None of these extracted engines
  was executed, and a BOOT16 file's presence does not prove the native path uses it.
- CONFIRMED: `SETUP.INI` names Bryce 4.0. Disc root has `data1.cab`, `data1.hdr`,
  `_sys1.cab/.hdr`, `_user1.cab/.hdr`, `setup.ins`, `_SETUP.LIB`, `data.1`,
  and supplemental layout/language data. `data1.cab` starts with `49 53 63 28`
  rather than Microsoft CAB magic. 7-Zip failed to open it as CAB.
  CONFIRMED: a locally built Unshield reader lists and successfully tests all 146
  entries of data1.cab. Selected files extracted without executing them.
- CONFIRMED original application: package `Program Files/Bryce4.exe`, 2,793,472
  bytes, PE32/x86, fixed version 4.0.0.13, SHA-256
  `2c736c50e7f95faa04afb074c96ed0d05f50b6dad648cb6e877850c4e555d0ea`.
  Static imports include Axiom.dll, ImageIOB4.dll, amberkrn.dll and MSVCRT.dll,
  alongside Windows DLLs. Selected application-local dependencies also parse as
  x86 PE32. Actual installed layout, registration, and runtime behavior UNKNOWN.
- CONFIRMED on Windows 11 25H2/build 26200: CreateProcessW reports error 740.
  After user-authorized UAC launch, setup remained running with no top-level
  windows or observed children. Thread wait-chain traversal repeatedly showed
  its main thread blocked on SendMessage to NIHardwareAccessibilityHelper.exe.
  That external process had hidden windows that failed WM_NULL probes. This is
  the observed wait, not proof of a universal Bryce bug or a complete workaround.
  Accessing the elevated setup's wait chain required elevated diagnostics.
  The helper was not terminated or changed. Installation remains incomplete.
- CONFIRMED: readme discusses a separate Content CD; this image also includes
  model/texture libraries, sample scenes, documentation, QuickTime30.exe,
  Acrobat Reader and optional-looking exporters. Presence alone does not prove
  runtime necessity. Application installation completeness is UNKNOWN until
  installation testing; optional second-disc coverage is UNKNOWN. A successful
  cabinet test confirms archive readability, not installation completeness.
- HFS/hybrid layout: UNKNOWN; only ISO view inspected, no Mac resource executed.
- Evidence: ignored `reports/bryce4-iso-listing.txt` and
  `reports/bryce4-installer-inventory.json`; selected root files were extracted
  read-only from the ISO into ignored `extracted-media/bryce4-install` using
  exact filenames and no overwrite. This subset is not a deployable installation.
  A path-sanitized static inventory is retained in
  `docs/evidence/bryce4-installer-inventory.json`; it contains metadata, not binaries.
- Both images were mounted read-only with user authorization on 25 November.
  Windows-visible full inventories contain 351 Bryce 4 files and 1,212 Bryce 3D
  files, with zero traversal/read errors. Windows ISO view differs from the
  external 7-Zip listing; HFS completeness remains unverified.
- Local evidence: `reports/bryce4-media-inventory.json`,
  `reports/bryce4-payload-inventory.json`, `reports/bryce4-data1-test.txt`,
  `reports/bryce4-wait-chain-elevated.json`, and follow-up snapshots.
- Next runtime experiment: user saves audio work and closes the implicated
  Native Instruments helper, then observe whether setup advances or encounters
  another blocker. Do not terminate unrelated apps, patch setup, or apply
  arbitrary compatibility modes to bypass this wait.

## Bryce 3D

- CONFIRMED media: `Bryce3DCD/Bryce3DCD.iso`, 488,787,968 bytes, SHA-256
  `f72700049a75773b60f22e0d0cf4ad87de63470151b7d8df45f897135a33ee8d`.
- Root SETUP.EXE: 45,568 bytes, NE/16-bit, SHA-256
  `64d55b0367abf8456498cfcad956f642972b720b116f829c54f3251513c1ef2f`.
  Root _ISDEL.EXE and _SETUP.DLL also classify as NE. No attempt to execute
  these unsupported segmented binaries was made.
- Deark decoded the InstallShield Z `data.1` archive into 93 files for static
  analysis. `prog/Bryce 3D.exe`: 2,357,760 bytes, PE32/x86, version 3.0.0.0,
  SHA-256 `7cceb0d75130a70a9783e43aab089bdb27bf9e060f9ea7f0a2ba02b7e399ebe7`.
  Direct imports include Axiom.dll, amberkrn.dll, MSVCRT.dll, WINMM.dll,
  AVIFIL32.dll, MSVFW32.dll and ordinary Windows GUI DLLs. Graphics-specific
  Amber DLLs and plugins exist in the payload; runtime API selection is untested.
- `_INST32I.EX_` decodes to x86 INSTALL.EXE and WUTL95i.DLL, with NE LZWSERV.EXE
  and BOOT16.EXE. The coexistence of these files does not establish whether the
  32-bit engine can complete installation independently of 16-bit components.
- Local evidence: `reports/bryce3-media-inventory.json`,
  `reports/bryce3-engine-inventory.json`, and `reports/bryce3-payload-inventory.json`.
- Installation and application functionality: NOT TESTED.
- No shared compatibility settings inferred from Bryce 4.
- Next experiment: investigate the original 32-bit installation engine and
  setup metadata before proposing a replacement installation process.

## What the tools establish

Static format detection and a hash establish file properties, not whether Bryce
works. Import names do not prove runtime graphics API usage or missing DLLs.
Process creation, a responsive WM_NULL probe, and visible windows are separate
observations; none is a scene-editing or rendering test.

The user supplied both archives. The agent downloaded only open-source analysis
tool source code. Original media and extracted payloads remain in ignored local
folders. The only original executable run was Bryce 4's root setup.

External readers were built locally, not added as toolkit runtime dependencies:
[Deark](https://github.com/jsummers/deark) commit
`e294a6e8348bd93f9a9305bb5f67d0042db4b791` and
[Unshield](https://github.com/twogood/unshield) commit
`3914dffb32ad05ebcb3e7f64a033e69b59127f47`, using zlib v1.3.1.
Their extracted names/group directories are analysis output, not an installation
layout. Reproduction notes are in `docs/analysis-tools.md`.

Wait diagnostics follow Microsoft's documented
[GetThreadWaitChain API](https://learn.microsoft.com/windows/win32/api/wct/nf-wct-getthreadwaitchain).

Binary parsing follows Microsoft's [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
JSON uses [nlohmann/json v3.12.0](https://github.com/nlohmann/json/releases/tag/v3.12.0)
(MIT), vendored with its license. Header SHA-256:
`aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63`.
