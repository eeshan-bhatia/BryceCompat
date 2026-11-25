$ErrorActionPreference = 'Stop'
# Deliberately inspect Git's tracked set, not the user's ignored media or builds.
# Windows PowerShell drops empty inherited values, which can break injected
# GIT_CONFIG_COUNT pairs. This local read needs no injected Git configuration.
$savedConfigCount = $env:GIT_CONFIG_COUNT
try {
    $env:GIT_CONFIG_COUNT = '0'
    $tracked = @(& git -C "$PSScriptRoot/.." ls-files)
    if ($LASTEXITCODE) { throw 'Unable to enumerate tracked files' }
} finally { $env:GIT_CONFIG_COUNT = $savedConfigCount }
$forbidden = @($tracked | Where-Object {
    $_ -match '(?i)(^|/)(original-media|extracted-media|bryce4|bryce3dcd|bryce3d|reports|dist|local-analysis)/' -or
    $_ -match '(?i)\.(iso|img|dmg|hfs|exe|dll|cab|ex_|ins|obp|br3|br4|bry|wri)$'
})
if ($forbidden.Count) { throw "Original media or binary artifacts must not be tracked:`n$($forbidden -join "`n")" }
Write-Output "Source-only guard passed for $($tracked.Count) tracked files. Review newly added assets manually as well."
