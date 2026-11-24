# Investigating installation

No installation recipe is verified yet. Supply original licensed media as a
mounted CD-ROM or extracted Windows directory. For a hybrid disc, this release
can inspect only the filesystem exposed by Windows; it does not read HFS.
An ISO file itself can be hashed but must be mounted/extracted by the user for
file inventory. Administrator rights are not requested by the scanner.

1. Run `brycecompat detect --media "D:\media" --json`.
2. Run `brycecompat scan "D:\media" --json --output inventory.json`.
3. Run `brycecompat doctor --installer "D:\media\setup.exe" --json`.
4. Review the file architecture and dependencies. Obtain explicit permission
   from the owner before any execution of original software.
5. To execute an approved installer, use `doctor --installer <path> --run
   --consent --timeout-ms 5000 --json`. This can alter the machine through the
   original installer; BryceCompat does not intercept or roll back its actions.
6. Alternatively use `doctor --pid <existing-pid> --json` without launching it.

No arbitrary compatibility mode, registry entry, runtime dependency, or package
extraction is applied. Investigate native behavior first. Do not infer that a
running process with no visible window is 16-bit or crashed. Preserve reports
and compare windows, child processes, and exit status before further experiments.

Optional Bryce 4 second-disc assets must be distinguished from required runtime
files after inspection. Missing optional media is not itself a startup failure.
