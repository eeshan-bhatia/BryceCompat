param([Parameter(Mandatory)][string]$Cli, [Parameter(Mandatory)][string]$Fixture)
$ErrorActionPreference = 'Stop'
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
$scan = & $Cli scan $Fixture --json | ConvertFrom-Json
Assert ($LASTEXITCODE -eq 0) 'Scan failed'
Assert ($scan.files[0].analysis.format -eq 'PE32+') 'Built fixture architecture incorrect'
$ErrorActionPreference = 'Continue'
& $Cli doctor --installer $Fixture --run 2>$null
$denied = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Assert ($denied -eq 2) 'Installer consent gate failed'
$ErrorActionPreference = 'Continue'
& $Cli doctor --installer $Fixture --elevate 2>$null
$invalidElevation = $LASTEXITCODE
& $Cli launch --exe $Fixture --elevate 2>$null
$elevationDenied = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Assert ($invalidElevation -eq 2 -and $elevationDenied -eq 2) 'Elevation bypassed launch/consent gate'
$static = & $Cli doctor --installer $Fixture --json | ConvertFrom-Json
Assert ($LASTEXITCODE -eq 0 -and $static.executed -eq $false) 'Doctor executed implicitly'
$dry = & $Cli launch --exe $Fixture --dry-run --json | ConvertFrom-Json
Assert ($LASTEXITCODE -eq 0 -and $dry.executed -eq $false) 'Dry run executed'
$run = & $Cli launch --exe $Fixture --consent --timeout-ms 300 --json | ConvertFrom-Json
Assert ($LASTEXITCODE -eq 0 -and $run.process_created) 'CreateProcess failed'
Assert ($run.observation_elapsed_while_running -and $null -eq $run.exit_code) 'Timeout misclassified'
Assert ($run.snapshot.processes[0].windows.Count -ge 1) 'Hidden fixture window not found'
Assert (-not $run.snapshot.processes[0].windows[0].visible) 'Hidden window visibility incorrect'
Assert ($run.snapshot.processes[0].windows[0].responsive_probe) 'Responsive fixture reported unresponsive'
Assert ($run.snapshot.processes[0].threads.Count -ge 1) 'Thread inventory missing'
$exited = & $Cli launch --exe $Fixture --consent --timeout-ms 5000 --json | ConvertFrom-Json
Assert ($LASTEXITCODE -eq 0 -and $exited.exit_code -eq 37) 'Exit code missing'
Assert (-not $exited.observation_elapsed_while_running) 'Exit misclassified'
Write-Output 'CLI consent, static diagnostics, dry run, launch, timeout, and exit checks passed'
