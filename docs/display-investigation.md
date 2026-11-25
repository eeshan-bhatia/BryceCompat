# Bryce 4 display investigation

The installed original Bryce 4 executable (4.0.0.13) started without elevation
on the Windows 11 test host after the user completed the original installer.
Its SHA-256 matches the previously inspected original payload:
`2c736c50e7f95faa04afb074c96ed0d05f50b6dad648cb6e877850c4e555d0ea`.

The read-only `doctor --pid <pid> --json` report now includes physical window
and client rectangles, monitor/work-area rectangles, monitor scale, window DPI
and DPI awareness, minimized/maximized state, resize styles and whether a
window covers its monitor. Only the diagnostic thread temporarily changes DPI
context, then restores it. Target settings and display resolution are unchanged.

On this host, two visible nonempty Bryce windows have both outer and client
bounds `[0, 0, 1920, 1080]`, covering the primary monitor. Both respond to the
window probe, report DPI-unaware status and 96 DPI, and lack standard maximize
and resize styles. Monitor scaling is 100%. The taskbar work area ends at 1032.
These measurements do not prove correct rendering or usable input.

The reported small interface and black areas are not yet visually classified:
the desktop automation tool does not expose a targetable Bryce window, even
after the user brings it forward. A user screenshot is needed. Simply enlarging
an already monitor-sized window is not supported as a fix by this evidence.
No forced resizing, DPI override, resolution change or executable patch has
been applied. No fullscreen or scaling fix is claimed.

Local raw reports remain ignored. Public evidence contains no registration
data, original application files or screenshots of proprietary assets.
