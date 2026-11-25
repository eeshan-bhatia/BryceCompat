# Local-only archive investigation

All paths below are ignored development storage. Do not add tool build trees or
extracted commercial files to Git. These commands describe the observed static
investigation; they do not implement installation or license verification.

Source revisions used (built with local MSVC 19.52):

- Deark `e294a6e8348bd93f9a9305bb5f67d0042db4b791`, from
  https://github.com/jsummers/deark (MIT-style license, bundled-code notices).
- Unshield `3914dffb32ad05ebcb3e7f64a033e69b59127f47`, from
  https://github.com/twogood/unshield (MIT).
- zlib v1.3.1, commit `51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf`, from
  https://github.com/madler/zlib (zlib license).

Deark's `proj/vs2022/deark.vcxproj` built using MSBuild Release/x64 with
`PlatformToolset=v145` and `DebugInformationFormat=OldStyle`. Other installed
toolsets may require different values. Unshield uses CMake/NMake, `BUILD_STATIC=ON`,
`BUILD_TESTING=OFF`, `CMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded`, and `ZLIB_ROOT`
pointing at the locally built zlib install. Reader builds do not count as tests
of all reader functionality; only the supplied-file operations below were run.

Deark `-l <file>` lists `_INST32I.EX_` and Bryce 3D `data.1`. For static extraction,
use a fresh ignored output directory with `-n -od <directory> <file>`. Default
numbered flattened names were intentionally retained for analysis. They cannot
be copied verbatim into an installation and expected to work.

Unshield `l data1.cab` listed 146 Bryce 4 entries; `t data1.cab` tested all 146
successfully. Selected application files were extracted with:

```text
unshield -j -d <fresh-analysis-directory> x data1.cab Bryce4.exe Axiom.dll AmberKrn.dll ImageIOB4.dll qtmlClient.dll
```

Keep `data1.hdr` beside the cabinet. Preserve original media and hashes. The
extractor's group names (such as `Program_Files`) are not proven installation
destinations. Do not run these selected files as an allegedly complete install.
Do not automatically extract arbitrary archives into an existing installation.
