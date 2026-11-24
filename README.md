# BryceCompat

Native Windows investigation toolkit for preserving MetaCreations Bryce 3D and
Bryce 4 on Windows 11 x64. **Current status: diagnostic foundation; original
Bryce installation and functionality are NOT TESTED.** This does not yet install
Bryce or apply compatibility fixes. It never bundles original commercial media.

## Build

Requires MSVC C++ tools, Windows SDK, CMake 3.25+, and PowerShell. JSON is vendored
(nlohmann/json 3.12.0, MIT); normal builds need no dependency downloads.

From an x64 Native Tools Command Prompt:

```bat
cmake -S . -B build-native -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build-native
ctest --test-dir build-native --output-on-failure
cpack --config build-native/CPackConfig.cmake -C Release
```

Alternatively use a CMake version that supports your Visual Studio generator:
`cmake -S . -B build -A x64`, then build/test with `--config Release` / `-C Release`.

## Use

```powershell
.\build-native\brycecompat.exe --help
.\build-native\brycecompat.exe detect --media 'D:\original-media' --json
.\build-native\brycecompat.exe scan 'D:\mounted-or-extracted-disc' --json --output inventory.json
.\build-native\brycecompat.exe doctor --installer 'D:\disc\setup.exe' --json
.\build-native\brycecompat.exe doctor --pid 1234 --json
.\build-native\brycecompat.exe report --profile profiles/bryce4.json --json
```

Configure media with `--media`, `BRYCECOMPAT_MEDIA` (one path), or `detect --config`
using `{"schema_version":1,"media_paths":["D:/original-media"]}`. Relative config
paths resolve beside the config. Discovery checks CD-ROM drives, configured paths,
development media folders, and a small set of common installation locations.
It does not claim exhaustive installation detection.

`scan` hashes and inventories files without executing them. Direct ISO/HFS
parsing is unavailable: mount or extract media yourself. `doctor` is static by
default; execution requires both `--run --consent`. Explicit application launch
uses `launch --exe <path> --consent`; `--dry-run` inspects without execution.
An observation timeout leaves the process running and does not mean a crash.
Original installers may make their own changes; this tool cannot undo those.

Exit codes: 0 successful tool operation; 2 usage/consent error; 3 operation error;
4 partial scan. A successful tool operation never implies Bryce compatibility.
Report output refuses existing files. Reports may contain local paths and static
manifest content; review before sharing. No telemetry or automatic uploads.

See [progress](PROGRESS.md), [investigation](docs/investigation.md),
[installation experiments](docs/installation.md), [architecture/limits](docs/architecture.md),
[testing](docs/testing.md), and [compatibility matrix](docs/compatibility-matrix.md).

New code is MIT licensed. Unofficial preservation project; not affiliated with
or endorsed by MetaCreations or Bryce's rights holders. Supply your own properly
licensed software. Never commit original ISOs, extracted commercial content,
executables, scenes, serial numbers, or proprietary assets. Ignore rules protect
common media extensions and designated media folders, not every possible asset.
