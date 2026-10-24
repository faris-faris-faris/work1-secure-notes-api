# Run the same four checks as .github/workflows/ci.yml, locally.
# Use this to produce the CI evidence on a machine that cannot push, or to
# reproduce a red pipeline without waiting for GitHub.
#
#   powershell -ExecutionPolicy Bypass -File .\scripts\ci-local.ps1
param(
    [string]$OutFile = 'docs/evidence/ci-local.txt'
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFile) | Out-Null

$results = @()
$lines = New-Object System.Collections.Generic.List[string]

function Section([string]$title) {
    $line = "`n=== $title ==="
    Write-Host $line -ForegroundColor Cyan
    $script:lines.Add($line)
}

function Run([string]$name, [scriptblock]$command) {
    & $command 2>&1 | ForEach-Object {
        Write-Host $_
        $script:lines.Add([string]$_)
    }
    $code = $LASTEXITCODE
    $script:results += [pscustomobject]@{ Job = $name; Exit = $code; Status = $(if ($code -eq 0) { 'PASS' } else { 'FAIL' }) }
}

Section 'job: test (node --test)'
Run 'test' { node --test --test-reporter=spec }

Section 'job: lint (eslint --max-warnings=0)'
Run 'lint' { npx eslint . --max-warnings=0 }

Section 'job: sast (eslint-security)'
Run 'sast' {
    npx eslint . --format json --output-file eslint-report.json
    node scripts/sast-summary.mjs eslint-report.json
}

Section 'job: sca (OSV.dev — CI runs npm audit)'
Write-Host 'note: the local npm mirror does not implement the audit endpoint; OSV covers the same dependency tree.' -ForegroundColor DarkGray
Run 'sca' { node scripts/sca-osv.mjs }

Section 'pipeline summary'
$summary = $results | Format-Table -AutoSize | Out-String
Write-Host $summary
$lines.Add($summary)
$failed = @($results | Where-Object { $_.Exit -ne 0 }).Count
$verdict = if ($failed -eq 0) { "RESULT: all $($results.Count) jobs passed" } else { "RESULT: $failed of $($results.Count) jobs failed" }
Write-Host $verdict -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })
$lines.Add($verdict)

$lines -join "`n" | Set-Content -Path $OutFile -Encoding utf8
exit $failed
