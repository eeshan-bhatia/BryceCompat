# Compatibility matrix

Both Windows-visible media filesystems and application payloads were inspected.
No compatibility fix is verified. Static media evidence is in investigation.md.

| Functional area | Bryce 3D | Bryce 4 |
|---|---|---|
| Media inventory | PASS (Windows view) | PASS (Windows view) |
| Application payload identity | PASS (static x86 identification) | PASS (static x86 identification) |
| Original installer GUI | NOT TESTED (NE bootstrapper) | PASS on retry (Product Registration reached); prior message wait recorded |
| Install, shortcuts, restart | NOT TESTED | NOT TESTED |
| GUI initialization and normal exit | NOT TESTED | NOT TESTED |
| Scene and object editing | NOT TESTED | NOT TESTED |
| Terrain editing | NOT TESTED | NOT TESTED |
| Materials and lighting | NOT TESTED | NOT TESTED |
| Rendering and export | NOT TESTED | NOT TESTED |
| Save and reopen scenes | NOT TESTED | NOT TESTED |
| Animation and codecs | NOT TESTED | NOT TESTED |

Application and setup hashes are recorded in profiles and the investigation
report. Profiles contain no verified fixes. Runtime observation was on Windows
11 25H2/build 26200, native configuration with UAC elevation only; the external
Native Instruments message wait is machine-specific evidence. It has not been
shown to be the only blocker. Full installation verification remains pending
licensed serial entry. No rollback tests are applicable because toolkit mutations
and replacement installation are not implemented.
