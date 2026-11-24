# Architecture and limits

`brycecompat_core` shares bounded static binary parsing, recursive inventory,
SHA-256, profile validation, discovery, Windows process launch and observations.
The CLI provides explicit intent/consent gates and structured output. There are
no runtime hooks, global settings, registry writes, or executable patches.

The binary reader uses checked little-endian reads and file-backed RVA mapping.
Parser budgets cap sections, import strings/thunks, and resource traversal.
Files over 256 MiB are streamed for hashing but not loaded for binary parsing.
Resources include numeric/named identities, raw manifest bytes, and fixed file
version data. Version string tables, NE imports, delay-load imports, archive
extraction, HFS and direct ISO filesystem parsing remain unsupported.

Directory reparse points are skipped to avoid escaping the selected media tree.
Scanning is read-only but does not sandbox filesystem races: use stable offline
media, not a directory concurrently modified by an adversary. Scans hash every
file, including assets; this may take time. File modification during hashing and
parsing is not currently detected. Release identity remains UNKNOWN until
verified media establishes a reliable classifier; filenames alone are not proof.

Process snapshots show current descendant relationships only. They may miss
short-lived or reparented processes and are subject to PID reuse. Window probes
are observations, not a hang diagnosis. No event-log collection or dependency
resolution is implemented. Launch preserves inherited environment and uses the
executable's parent as working directory. UAC-required executables return the
Windows error; the tool does not automatically elevate.

Reports include paths and static resource content. They are printed or saved
only on request. Automatic per-user logging, automatic export redaction,
transactional installation, registry rollback, and the GUI remain future work.
Do not treat this diagnostic build as the finished compatibility toolkit.
