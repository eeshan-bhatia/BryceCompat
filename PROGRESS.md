# Progress — 26 November 2026

## Implemented

- C++20/MSVC/CMake core and usable CLI: scan, detect, static/explicit-run doctor,
  consent-gated launch, PID observations, profile reports, JSON and readable output.
- Checked MZ/NE/PE32/PE32+ classification, machine architecture, normal imports
  by name/ordinal, resource identities, embedded manifest bytes, fixed file version.
- Streamed SHA-256, file inventories, configurable discovery, CD-ROM candidates,
  reparse-point exclusion, bounded parsing, output overwrite protection.
- Unicode CreateProcessW with executable-directory working directory; process
  and current descendant snapshots, exit/bitness/window/WM_NULL observations.
  No automatic process termination or arbitrary compatibility flags.
- Separate unverified release profiles, synthetic tests, Windows CI definition,
  portable ZIP packaging, MIT license and documentation.
- Thread wait-chain diagnostics identify cross-process window-message waits,
  record access failures, and never enable debug privileges or terminate apps.
- Structured launch errors and explicit `--elevate` using the standard UAC prompt.
- InstallShield/MS CAB signature hints and a source-only Git/CI guard.
- Read-only display diagnostics: physical window/client bounds, monitor bounds,
  scale, DPI awareness, resize styles and monitor coverage. Observer DPI context
  is restored after inspection; no target window or display settings are changed.

## Verified

- Clean Windows x64 Release build using MSVC 19.52.37029, Windows SDK and CMake
  3.31.8/NMake. Embedded debug information avoids the PDB-manager failure seen
  in the initial compiler probe. Static MSVC runtime selected for distribution.
- Host reports Windows 11 25H2, build 26200. Portable package generated at
  `dist/BryceCompat-0.1.0-win64.zip`; main binary imports only Windows DLLs
  (including bcrypt, ADVAPI32, USER32, KERNEL32 and now SHELL32).
- Current CTest: 4/4 passing, including the source-only guard. Extended core run:
  2,562 checks (thread-count-dependent) including deterministic
  malformed inputs, SHA-256 known answer, Unicode paths, version/resource/import
  parsing, profile rejection, report overwrite refusal, and process inspection.
- CLI integration: explicit consent gate, read-only doctor, dry-run, synthetic
  process creation, hidden responsive window, elapsed observation, exit code 37.
- User-supplied Bryce 4 ISO inventoried; selected setup components hashed and
  analyzed. Setup.exe is PE32/x86 InstallShield launcher 5.50.137.0, not 16-bit.
  See docs/investigation.md for precise hashes, evidence and limitations.
- Both supplied ISOs mounted read-only. Complete Windows-visible inventories:
  Bryce 3D 1,212 files, Bryce 4 351 files, zero traversal/read errors.
- Bryce 4 root setup executed with user authorization. Native launch required
  elevation (740); elevated setup reproduced the no-window symptom. Repeated
  WCT snapshots show a SendMessage wait on NIHardwareAccessibilityHelper.exe.
  No unrelated process was terminated. That initial attempt did not install.
- Retry with the Native Instruments helper absent reached the original Bryce 4
  Product Registration dialog. The helper and previous setup were already absent
  at preflight; the agent closed no apps. Original setup spawned its x86 internal
  engine and displayed the installer UI without compatibility flags or patches.
  The user subsequently completed installation manually. No serial is stored
  in project files or committed.
- Deark decoded Bryce 3D's 93-file data.1 and both internal engine archives.
  Unshield tested all 146 Bryce 4 data1.cab entries and extracted selected files.
  Both original applications are PE32/x86: Bryce 3D 3.0.0.0, Bryce 4 4.0.0.13.
  Application hashes and selected dependency metadata are recorded in profiles
  and docs. Bryce 4's installed original executable has now been launched without
  elevation and has responsive windows. Bryce 3D has not been run.
- Bryce 4 display baseline: two visible nonempty windows cover the primary
  1920x1080 monitor, with matching client bounds, DPI-unaware status, 96 window
  DPI and 100% monitor scaling. This is window geometry, not visual verification.
  Desktop automation cannot enumerate Bryce even after the user foregrounds it.
- Explicit CLI `--elevate` verified using our synthetic fixture (exit 37);
  structured error 740 reporting verified against original setup without
  launching a second copy. Invalid-image failures also tested synthetically.
- GitHub Actions workflow authored but no hosted run claimed.

## Unresolved and limitations

- Milestone 1 diagnostic foundation implemented; broader production hardening
  remains. Milestone 2 substantially investigated, but installation metadata and
  optional-disc completeness remain unresolved. Milestones 3–8 are not complete.
- Bryce 4 installation is user-reported complete and installed app startup is
  observed. Visual layout, asset completeness and functionality remain unverified.
- Bryce 3D root setup is NE/16-bit. Its internal INSTALL.EXE is x86, but other
  engine components are NE; an all-native installation route is unverified.
- No fully verified installation, replacement installer, registry changes, rollback,
  compatibility fixes, GUI launcher, scene/render/save/load test, or native Bryce
  functionality pass. Do not equate infrastructure tests with Bryce compatibility.
- ISO/HFS parsing is external/manual; duplicate asset paths need care. No NE
  import decoder, delay-import enumeration, complete version string decoding,
  dependency resolution, event-log capture, per-user log store or export redaction.
- Diagnostics are snapshots and may miss exited/reparented children. File trees
  should remain stable while scanning. Reports can contain local filesystem paths.

## Next actions

1. Obtain a user screenshot of Bryce's layout to distinguish unused workspace
   from scaling or rendering problems. No fullscreen adaptation is verified yet.
2. Establish original installation layout/registration from the installer and
   its metadata; do not treat extraction as installation.
3. Investigate Bryce 3D's original 32-bit engine and its dependencies separately.
4. Test one narrowly scoped reversible adaptation only for a confirmed failure.
5. Verify installation and original scene/render/save/load behavior before any
   compatibility claim; only then implement necessary adaptations and GUI flows.
