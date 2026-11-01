[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $IsWindows -and $env:OS -ne 'Windows_NT') {
    throw 'PawnIO can only be installed on Windows.'
}

if (-not (Test-IsAdministrator)) {
    $powerShell = (Get-Process -Id $PID).Path
    $scriptPath = $PSCommandPath
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $scriptPath))
    try {
        $elevatedProcess = Start-Process -FilePath $powerShell -Verb RunAs -ArgumentList $arguments -Wait -PassThru
        exit $elevatedProcess.ExitCode
    }
    catch {
        Write-Error "Administrator approval through UAC was not granted or installation could not start: $($_.Exception.Message)"
        exit 1
    }
}

$winget = Get-Command winget.exe -ErrorAction SilentlyContinue
if (-not $winget) {
    throw 'winget.exe was not found. Install Windows App Installer/WinGet or install PawnIO manually from its official GitHub release.'
}

Write-Host 'PawnIO is a system-level Windows driver.' -ForegroundColor Cyan
Write-Host 'It is used for low-level access to hardware sensors.'
Write-Host 'Official WinGet package ID: namazso.PawnIO'
$answer = Read-Host 'Do you want to start the PawnIO installation? (Y/N)'
if ($answer -notin @('Y', 'y', 'YES', 'yes')) {
    Write-Host 'Installation was cancelled by the user.' -ForegroundColor Yellow
    exit 0
}

& $winget.Source install --exact --id namazso.PawnIO --accept-source-agreements --accept-package-agreements
$wingetExitCode = $LASTEXITCODE
if ($wingetExitCode -ne 0) {
    throw "WinGet could not complete PawnIO installation. Exit code: $wingetExitCode"
}

Write-Host ''
Write-Host 'WinGet installation completed successfully.' -ForegroundColor Green
Write-Host 'To inspect driver status, run: py -3.14 system_analyses.py --diagnostics'
Write-Host 'Restart Windows if the installer requests it.'
[void](Read-Host 'Press Enter to close this window')
