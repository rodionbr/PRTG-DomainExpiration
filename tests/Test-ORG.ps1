param()
$scriptPath = Join-Path $PSScriptRoot '..' 'src' 'Check-DomainExpiration.ps1'
$output = & $scriptPath -Domain 'example.org' 2>$null | Out-String
if ($LASTEXITCODE -ne 0) {
    throw "Expected success for example.org, but got exit code $LASTEXITCODE"
}
if ($output -notmatch '<prtg>') {
    throw 'Expected PRTG XML output.'
}
Write-Host $output
