param([string]$CMake = 'cmake', [string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
# Run in an x64 Native Tools Command Prompt, including when MSVC is not on PATH.
& $CMake -S "$PSScriptRoot/.." -B "$PSScriptRoot/../build-native" -G 'NMake Makefiles' "-DCMAKE_BUILD_TYPE=$Configuration"
if ($LASTEXITCODE) { throw 'CMake configure failed' }
& $CMake --build "$PSScriptRoot/../build-native"
if ($LASTEXITCODE) { throw 'Build failed' }
$CTest = Join-Path (Split-Path (Get-Command $CMake).Source) 'ctest.exe'
& $CTest --test-dir "$PSScriptRoot/../build-native" --output-on-failure
if ($LASTEXITCODE) { throw 'Tests failed' }
