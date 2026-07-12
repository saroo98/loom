# Loom installer launcher (Windows PowerShell). Mutation policy lives in loom_install.py.

param(
    [switch]$Check,
    [switch]$Uninstall,
    [switch]$AdoptLegacy,
    [string]$UserHome = $HOME
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Installer = Join-Path $PSScriptRoot 'loom_install.py'
if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
    Write-Error "Missing installer engine: $Installer"
    exit 2
}

$Python = Get-Command python -ErrorAction SilentlyContinue
$PythonArgs = @()
if (-not $Python) {
    $Python = Get-Command py -ErrorAction SilentlyContinue
    if ($Python) { $PythonArgs += '-3' }
}
if (-not $Python) {
    Write-Error 'Python 3.11 or newer is required'
    exit 2
}

$PythonArgs += @($Installer, '--home', $UserHome)
if ($Check) { $PythonArgs += '--check' }
if ($Uninstall) { $PythonArgs += '--uninstall' }
if ($AdoptLegacy) { $PythonArgs += '--adopt-legacy' }

& $Python.Source @PythonArgs
exit $LASTEXITCODE
