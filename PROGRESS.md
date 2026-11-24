# Progress — 24 November 2026

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

## Verified

- Clean Windows x64 Release build using MSVC 19.52.37029, Windows SDK and CMake
  3.31.8/NMake. Embedded debug information avoids the PDB-manager failure seen
  in the initial compiler probe. Static MSVC runtime selected for distribution.
- Host reports Windows 11 25H2, build 26200. Portable package generated at
  `dist/BryceCompat-0.1.0-win64.zip`; main binary imports only Windows DLLs
  (bcrypt, ADVAPI32, USER32, KERNEL32), with no dynamic MSVC runtime dependency.
- CTest: 3/3 passing. Core executable: 2,547 checks including deterministic
  malformed inputs, SHA-256 known answer, Unicode paths, version/resource/import
  parsing, profile rejection, report overwrite refusal, and process inspection.
- CLI integration: explicit consent gate, read-only doctor, dry-run, synthetic
  process creation, hidden responsive window, elapsed observation, exit code 37.
- User-supplied Bryce 4 ISO inventoried; selected setup components hashed and
  analyzed. Setup.exe is PE32/x86 InstallShield launcher 5.50.137.0, not 16-bit.
  See docs/investigation.md for precise hashes, evidence and limitations.
- No original installer or Bryce application has been executed.
- GitHub Actions workflow authored but no hosted run claimed.

## Unresolved and limitations

- Milestone 1 diagnostic foundation implemented; broader production hardening
  remains. Milestone 2 partial: Bryce 4 application payload not yet decoded,
  Bryce 3D media not yet found. Milestones 3–8 are not complete.
- Bryce 4 no-window symptom not reproduced; cause UNKNOWN. 7-Zip cannot decode
  supplied data1.cab; investigate an InstallShield-aware package reader.
- No verified installation, replacement installer, registry changes, rollback,
  compatibility fixes, GUI launcher, scene/render/save/load test, or native Bryce
  functionality pass. Do not equate infrastructure tests with Bryce compatibility.
- ISO/HFS parsing is external/manual; duplicate asset paths need care. No NE
  import decoder, delay-import enumeration, complete version string decoding,
  dependency resolution, event-log capture, per-user log store or export redaction.
- Diagnostics are snapshots and may miss exited/reparented children. File trees
  should remain stable while scanning. Reports can contain local filesystem paths.

## Next actions

1. Inspect Bryce 3D ISO when supplied, independently from Bryce 4.
2. Inspect InstallShield payload using a validated compatible reader; determine
   executable, assets, required dependencies and installation metadata.
3. With explicit user authorization, mount Bryce 4 media and run root Setup.exe
   with process/window diagnostics. The extracted subset is for analysis only.
4. Reproduce the symptom, then test one narrowly scoped reversible change.
5. Verify installation and original scene/render/save/load behavior before any
   compatibility claim; only then implement necessary adaptations and GUI flows.
