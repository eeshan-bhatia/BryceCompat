# Testing and evidence

CTest runs the C++ checks, CLI help, and PowerShell CLI integration checks.
Tests generate synthetic MZ, NE, PE32 and PE32+ bytes; no original Bryce files
are needed or included. Malformed offsets, truncation, resource cycles, imports
by name/ordinal, hashing, Unicode paths, JSON profiles, and self-process
observation are covered. A locally compiled process sleeps and exits with 37
to test launch, elapsed observation, and exit status without legacy software.

GitHub Actions builds on Windows, runs CTest, and packages a portable ZIP.
The workflow being present does not mean a hosted CI run has passed.
The source-only guard checks tracked paths for original media and binary artifacts.
Additional checks cover package signatures, thread inventory, consent for
elevation, and structured CreateProcess failures using a synthetic invalid image.
On 25 November, an explicitly elevated synthetic fixture also exited with the
expected code 37. That interactive UAC-path test is separate from unattended CI.

## Local-only Bryce regression procedure

Record OS build, SHA-256 of original executable and installer, source-media
identity, profile, and observations for every run. Use PASS, FAIL, NOT TESTED,
or NOT APPLICABLE. Keep results under ignored `reports/`; review absolute paths
and any embedded manifest content before sharing. Never commit serials/assets.

For each version independently: verify installation and shortcut behavior;
restart and relaunch; check original GUI, controls, normal exit; create and
manipulate objects, camera and materials; create/edit terrain; render a simple
scene; save output; save and reopen the native scene with assets intact. Test
import/export and animation only for features actually present in that version.
Static scans and the synthetic launcher test do not satisfy these checks.
