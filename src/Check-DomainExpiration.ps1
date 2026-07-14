<#
.SYNOPSIS
    Checks the expiration date of a domain and returns XML for PRTG.

.DESCRIPTION
    This script queries domain registration data using RDAP first and WHOIS as a fallback.
    It supports common gTLDs and selected country-code domains and is designed for
    PowerShell 4.0+ and PRTG Network Monitor external sensors.

.PARAMETER Domain
    Domain name to check, for example example-domain.com.

.PARAMETER WarningDays
    Number of days left that triggers WARNING status.

.PARAMETER CriticalDays
    Number of days left that triggers CRITICAL status.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Check-DomainExpiration.ps1 -Domain example-domain.com
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [int]$WarningDays = 30,
    [int]$CriticalDays = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RootDomain {
    <#
    .SYNOPSIS
        Extracts the registered domain from a hostname.
    #>
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }

    $value = $Name.Trim().ToLowerInvariant()
    $value = $value -replace '^https?://', ''
    $value = $value -replace '/.*$', ''

    if ($value -match '^[a-z0-9.-]+$') {
        $parts = $value.Split('.')
        if ($parts.Length -ge 2) {
            if ($value.EndsWith('.com.ua', [System.StringComparison]::OrdinalIgnoreCase) -or
                $value.EndsWith('.dp.ua', [System.StringComparison]::OrdinalIgnoreCase) -or
                $value.EndsWith('.kiev.ua', [System.StringComparison]::OrdinalIgnoreCase)) {
                return $value
            }
            return ($parts[$parts.Length - 2] + '.' + $parts[$parts.Length - 1])
        }
    }

    return $value
}

function Get-SupportedZoneInfo {
    <#
    .SYNOPSIS
        Returns the list of supported zones and their WHOIS/RDAP providers.
    #>
    param([string]$Name)

    $zone = $null
    $parts = $Name.Split('.')
    if ($parts.Length -gt 1) {
        $zone = '.' + $parts[$parts.Length - 1]
    }

    $map = @{
        '.com' = @{ Provider = 'rdap'; RdapUrl = 'https://rdap.verisign.com/com/v1/domain/'; WhoisHost = 'whois.verisign-grs.com' }
        '.net' = @{ Provider = 'rdap'; RdapUrl = 'https://rdap.verisign.com/net/v1/domain/'; WhoisHost = 'whois.verisign-grs.com' }
        '.org' = @{ Provider = 'rdap'; RdapUrl = 'https://rdap.verisign.com/org/v1/domain/'; WhoisHost = 'whois.pir.org' }
        '.ua' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.ua' }
        '.com.ua' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.com.ua' }
        '.dp.ua' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.dp.ua' }
        '.wine' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.nic.wine' }
        '.pro' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.nic.pro' }
        '.cy' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.nic.cy' }
        '.bg' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.register.bg' }
        '.ae' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.aeda.net.ae' }
        '.kiyv.ua' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.kiev.ua' }
    }

    foreach ($entry in $map.Keys) {
        if ($Name.EndsWith($entry, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $map[$entry]
        }
    }

    return $null
}

function Send-WhoisQuery {
    <#
    .SYNOPSIS
        Sends a WHOIS query over TCP port 43.
    #>
    param(
        [string]$Host,
        [string]$Domain,
        [int]$TimeoutMs = 10000,
        [int]$Retries = 3
    )

    $attempt = 0
    while ($attempt -lt $Retries) {
        $attempt++
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.SendTimeout = $TimeoutMs
            $client.ReceiveTimeout = $TimeoutMs
            $connect = $client.ConnectAsync($Host, 43)
            if (-not $connect.Wait($TimeoutMs)) {
                throw 'Connection timed out'
            }
            $stream = $client.GetStream()
            $writer = New-Object System.IO.StreamWriter($stream)
            $writer.WriteLine($Domain)
            $writer.Flush()
            $reader = New-Object System.IO.StreamReader($stream)
            $content = $reader.ReadToEnd()
            $writer.Dispose()
            $reader.Dispose()
            $stream.Dispose()
            $client.Dispose()
            return $content
        }
        catch {
            if ($attempt -ge $Retries) {
                throw
            }
        }
    }

    throw 'WHOIS query failed after retries.'
}

function Get-RdapData {
    <#
    .SYNOPSIS
        Queries RDAP over HTTPS for the expiration date.
    #>
    param([string]$Url)

    try {
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Timeout = 10000
        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $content = $reader.ReadToEnd()
        $reader.Dispose()
        $response.Dispose()
        return $content
    }
    catch {
        return $null
    }
}

function Get-ExpirationDateFromText {
    <#
    .SYNOPSIS
        Extracts an expiration date from WHOIS or RDAP text.
    #>
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $patterns = @(
        'Registry Expiry Date',
        'Expiration Date',
        'Registry Expiration Date',
        'expires',
        'paid-till',
        'expire',
        'renewal date'
    )

    foreach ($pattern in $patterns) {
        $match = [regex]::Match($Text, '(?i)' + [regex]::Escape($pattern) + '\s*[:=]\s*([^\r\n]+)')
        if ($match.Success) {
            $value = $match.Groups[1].Value.Trim()
            $value = $value -replace '[^0-9A-Za-z:\-\. ]', ''
            $value = $value.Trim()
            if ($value) {
                return $value
            }
        }
    }

    return $null
}

function Get-RdapExpirationDate {
    <#
    .SYNOPSIS
        Parses the expiration date from an RDAP JSON response.
    #>
    param([string]$JsonText)

    if ([string]::IsNullOrWhiteSpace($JsonText)) { return $null }

    try {
        $json = $jsonText | ConvertFrom-Json
    }
    catch {
        return $null
    }

    if ($json.events) {
        foreach ($event in @($json.events)) {
            if ($event.eventAction -match 'expiration|expire|renew') {
                return $event.eventDate
            }
        }
    }

    return $null
}

function Get-ReferralHost {
    <#
    .SYNOPSIS
        Extracts a referral WHOIS host from the response text.
    #>
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $patterns = @('Registrar WHOIS Server', 'Whois Server')
    foreach ($pattern in $patterns) {
        $match = [regex]::Match($Text, '(?i)' + [regex]::Escape($pattern) + '\s*[:=]\s*([^\r\n]+)')
        if ($match.Success) {
            return $match.Groups[1].Value.Trim()
        }
    }

    return $null
}

function Convert-ToDateTimeUtc {
    <#
    .SYNOPSIS
        Converts various date formats to UTC DateTime.
    #>
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $normalized = $Value.Trim()
    $normalized = $normalized -replace 'T', ' '
    $normalized = $normalized -replace 'Z$', ''
    $normalized = $normalized -replace '\.$', ''

    $candidates = @(
        'yyyy-MM-dd HH:mm:ss',
        'yyyy-MM-dd HH:mm',
        'yyyy-MM-dd',
        'yyyy.MM.dd',
        'dd-MMM-yyyy',
        'dd-MMM-yyyy HH:mm:ss',
        'dd-MMM-yyyy HH:mm'
    )

    foreach ($format in $candidates) {
        try {
            $parsed = [datetime]::ParseExact($normalized, $format, [System.Globalization.CultureInfo]::InvariantCulture)
            return $parsed.ToUniversalTime()
        }
        catch {
        }
    }

    try {
        return ([DateTimeOffset]::Parse($normalized, [System.Globalization.CultureInfo]::InvariantCulture)).ToUniversalTime().DateTime
    }
    catch {
    }

    try {
        return ([datetime]$normalized).ToUniversalTime()
    }
    catch {
    }

    return $null
}

function Get-DaysRemaining {
    <#
    .SYNOPSIS
        Calculates how many days remain until an expiration date.
    #>
    param([datetime]$ExpirationDate)

    $now = [datetime]::UtcNow
    return [int](($ExpirationDate - $now).TotalDays)
}

function Get-Status {
    <#
    .SYNOPSIS
        Maps days remaining to PRTG status.
    #>
    param(
        [int]$DaysRemaining,
        [int]$WarningDays,
        [int]$CriticalDays
    )

    if ($DaysRemaining -le $CriticalDays) { return 'CRITICAL' }
    if ($DaysRemaining -le $WarningDays) { return 'WARNING' }
    return 'OK'
}

function Write-PrtgXml {
    <#
    .SYNOPSIS
        Writes a PRTG-compatible XML result.
    #>
    param(
        [string]$Status,
        [string]$Message,
        [int]$Value,
        [string]$Text
    )

    $xml = @"
<prtg>
  <result>
    <channel>Days Remaining</channel>
    <value>$Value</value>
    <unit>Count</unit>
    <float>0</float>
    <showtime>0</showtime>
    <text>$Text</text>
  </result>
  <error>0</error>
  <summary>$Message</summary>
</prtg>
"@

    Write-Output $xml
}

function Write-PrtgError {
    <#
    .SYNOPSIS
        Writes an error XML payload for PRTG.
    #>
    param([string]$Message)

    $xml = @"
<prtg>
  <error>1</error>
  <summary>$Message</summary>
</prtg>
"@

    Write-Output $xml
}

try {
    $resolvedDomain = Get-RootDomain -Name $Domain
    if (-not $resolvedDomain) {
        Write-PrtgError -Message 'Domain not found.'
        exit 1
    }

    $zoneInfo = Get-SupportedZoneInfo -Name $resolvedDomain
    if (-not $zoneInfo) {
        Write-PrtgError -Message 'Unsupported domain zone.'
        exit 1
    }

    $raw = $null
    $whoisHost = $null
    $source = $null

    if ($zoneInfo.Provider -eq 'rdap') {
        $rdapUrl = $zoneInfo.RdapUrl + $resolvedDomain
        $raw = Get-RdapData -Url $rdapUrl
        if ($raw) {
            $source = 'RDAP'
        }
    }

    if (-not $raw) {
        $whoisHost = $zoneInfo.WhoisHost
        $raw = Send-WhoisQuery -Host $whoisHost -Domain $resolvedDomain
        if ($raw) {
            $source = 'WHOIS'
        }
    }

    if (-not $raw) {
        Write-PrtgError -Message 'Expiration date not found.'
        exit 1
    }

    $dateValue = Get-ExpirationDateFromText -Text $raw
    if (-not $dateValue -and $source -eq 'RDAP') {
        $dateValue = Get-RdapExpirationDate -JsonText $raw
    }

    if (-not $dateValue) {
        $referralHost = Get-ReferralHost -Text $raw
        if ($referralHost) {
            $whoisHost = $referralHost
            $raw = Send-WhoisQuery -Host $whoisHost -Domain $resolvedDomain
            $source = 'Referral WHOIS'
            $dateValue = Get-ExpirationDateFromText -Text $raw
        }
    }

    if (-not $dateValue) {
        Write-PrtgError -Message 'Expiration date not found.'
        exit 1
    }

    $expirationDate = Convert-ToDateTimeUtc -Value $dateValue
    if (-not $expirationDate) {
        Write-PrtgError -Message 'Expiration date not found.'
        exit 1
    }

    $daysRemaining = Get-DaysRemaining -ExpirationDate $expirationDate
    $status = Get-Status -DaysRemaining $daysRemaining -WarningDays $WarningDays -CriticalDays $CriticalDays

    $text = "Domain: $resolvedDomain`n`nExpires: $($expirationDate.ToString('yyyy-MM-dd'))`n`nRegistrar: Unknown"
    if ($source) {
        $sourceText = $source
        if ($whoisHost) {
            $sourceText = "${sourceText}: $whoisHost"
        }
        $text = "Domain: $resolvedDomain`n`nExpires: $($expirationDate.ToString('yyyy-MM-dd'))`n`nRegistrar: Unknown`n`n$sourceText"
    }

    Write-PrtgXml -Status $status -Message $status -Value $daysRemaining -Text $text
    exit 0
}
catch {
    Write-PrtgError -Message 'Expiration date not found.'
    exit 1
}
