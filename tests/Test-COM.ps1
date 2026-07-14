param()
$scriptPath = Join-Path $PSScriptRoot '..' 'src' 'Check-DomainExpiration.ps1'
& $scriptPath -Domain 'example.com' | Out-String | Write-Host
