param()
$scriptPath = Join-Path $PSScriptRoot '..' 'src' 'Check-DomainExpiration.ps1'
& $scriptPath -Domain 'example.ua' | Out-String | Write-Host
