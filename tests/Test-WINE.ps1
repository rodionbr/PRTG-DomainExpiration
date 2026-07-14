param()
$scriptPath = Join-Path $PSScriptRoot '..' 'src' 'Check-DomainExpiration.ps1'
& $scriptPath -Domain 'example.wine' | Out-String | Write-Host
