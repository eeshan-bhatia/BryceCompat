# Compatibility matrix

Bryce 4 ISO and selected installer components have been analyzed statically.
No compatibility fix is verified. Static media evidence is in investigation.md.

| Functional area | Bryce 3D | Bryce 4 |
|---|---|---|
| Media inventory | NOT TESTED | PASS (ISO listing and selected setup files only) |
| Application payload identity | NOT TESTED | NOT TESTED |
| Install, shortcuts, restart | NOT TESTED | NOT TESTED |
| GUI initialization and normal exit | NOT TESTED | NOT TESTED |
| Scene and object editing | NOT TESTED | NOT TESTED |
| Terrain editing | NOT TESTED | NOT TESTED |
| Materials and lighting | NOT TESTED | NOT TESTED |
| Rendering and export | NOT TESTED | NOT TESTED |
| Save and reopen scenes | NOT TESTED | NOT TESTED |
| Animation and codecs | NOT TESTED | NOT TESTED |

Application executable hashes: unknown. Bryce 4 setup hash is recorded in the
investigation report. Profiles: separate unverified `bryce3` and `bryce4`.
The host build recorded by infrastructure tests is not a Bryce test environment
result. No rollback tests are applicable yet because configuration mutations
and replacement installation are not implemented.
