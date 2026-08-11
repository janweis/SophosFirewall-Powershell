#requires -Version 5.1
<#
    .SYNOPSIS
    Installs Pester 5+ and runs the test suite. Used by the CI workflow.

    .DESCRIPTION
    Lives in a script rather than inline in the workflow because the shell a step
    runs in cannot be chosen from the matrix - GitHub rejects the matrix context in
    the 'shell' key. The workflow therefore has one step per shell, and both call
    this script, so the logic exists once.

    Windows PowerShell ships Pester 3.4.0 in Program Files. It wins over a newer
    version unless it is explicitly removed and the installed one force-imported,
    which is why that dance happens here and why the loaded version is asserted
    before any test runs: a silent fall back to Pester 3 makes the whole suite
    report success without running a single Pester 5 test.
#>
[CmdletBinding()]
param(
    [string]$TestPath = 'Tests',
    [string]$ModulePath = 'Modules',
    [string]$ResultPath = 'TestResults.xml'
)

$ErrorActionPreference = 'Continue'

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"

if (-not (Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [Version]'5.0.0' })) {
    Write-Host 'Installing Pester >= 5.0 ...'
    Install-Module -Name Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck -Scope CurrentUser
}

Remove-Module -Name Pester -ErrorAction SilentlyContinue
try {
    Import-Module -Name Pester -MinimumVersion 5.0 -Force -ErrorAction Stop
}
catch {
    Write-Error "Failed to import Pester >= 5.0: $_"
    exit 1
}

$loaded = Get-Module -Name Pester
if (-not $loaded -or $loaded.Version -lt [Version]'5.0.0') {
    Write-Error "Loaded Pester is $($loaded.Version); >= 5.0 is required. Aborting."
    exit 1
}
Write-Host "Using Pester $($loaded.Version)"

$modules = Join-Path $PWD $ModulePath
$env:PSModulePath = "$modules$([System.IO.Path]::PathSeparator)$env:PSModulePath"
Write-Host "Added to PSModulePath: $modules"

$testFiles = @(Get-ChildItem -Path $TestPath -Recurse -Filter '*.Tests.ps1' -ErrorAction SilentlyContinue)
if ($testFiles.Count -eq 0) {
    Write-Warning "No test files found under $TestPath"
    exit 0
}
Write-Host "Found $($testFiles.Count) test file(s)"

try {
    $config = New-PesterConfiguration
    $config.Run.Path = $testFiles.FullName
    $config.Run.PassThru = $true
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputFormat = 'NUnitXml'
    $config.TestResult.OutputPath = $ResultPath

    $results = Invoke-Pester -Configuration $config

    Write-Host "Test Results: Passed=$($results.PassedCount), Failed=$($results.FailedCount)"
    if ($results.FailedCount -gt 0) {
        Write-Error "Tests failed: $($results.FailedCount) failures"
        exit 1
    }
}
catch {
    Write-Error "Pester execution failed: $_"
    exit 1
}
