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

.PARAMETER EnableLogging
    Enables logging to the ProgramData folder.

.PARAMETER ManualExpirationDate
    Manually specify the expiration date when automatic lookup fails.

.PARAMETER ManualDaysRemaining
    Manually specify how many days remain until expiration when automatic lookup fails.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Check-DomainExpiration.ps1 -Domain example-domain.com
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [int]$WarningDays = 30,
    [int]$CriticalDays = 10,
    [datetime]$ManualExpirationDate,
    [int]$ManualDaysRemaining,
    [switch]$EnableLogging
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CacheTtlSeconds = 300
$script:CacheRoot = if ($env:ProgramData) { Join-Path $env:ProgramData 'PRTG-DomainExpiration\Cache' } else { Join-Path $PSScriptRoot 'Cache' }
$script:LogPath = if ($env:ProgramData) { Join-Path $env:ProgramData 'PRTG-DomainExpiration\Check-DomainExpiration.log' } else { Join-Path $PSScriptRoot 'Check-DomainExpiration.log' }

function Write-Log {
    param([string]$Message)
    if (-not $EnableLogging) { return }
    if (-not (Test-Path (Split-Path $script:LogPath -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $script:LogPath -Parent) -Force | Out-Null
    }
    Add-Content -Path $script:LogPath -Value ("[{0}] {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Message)
}

function Get-CacheFilePath {
    param([string]$Key)
    if (-not $Key) { return $null }
    $safe = [regex]::Replace($Key.ToLowerInvariant(), '[^a-z0-9]', '_')
    return Join-Path $script:CacheRoot ($safe + '.json')
}

function Get-CacheValue {
    param([string]$Key)
    $path = Get-CacheFilePath -Key $Key
    if (-not $path -or -not (Test-Path $path)) { return $null }
    try {
        $item = Get-Item -Path $path
        $ageSeconds = ((Get-Date).ToUniversalTime() - $item.LastWriteTimeUtc).TotalSeconds
        if ($ageSeconds -gt $script:CacheTtlSeconds) { return $null }
        $content = Get-Content -Path $path -Raw
        return $content | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function Set-CacheValue {
    param([string]$Key,[object]$Value)
    $path = Get-CacheFilePath -Key $Key
    if (-not $path) { return }
    if (-not (Test-Path $script:CacheRoot)) {
        New-Item -ItemType Directory -Path $script:CacheRoot -Force | Out-Null
    }
    $Value | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
}

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

    $map = @{
        '.com' = @{ Provider = 'rdap'; RdapUrl = 'https://rdap.verisign.com/com/v1/domain/'; WhoisHost = 'whois.verisign-grs.com' }
        '.net' = @{ Provider = 'rdap'; RdapUrl = 'https://rdap.verisign.com/net/v1/domain/'; WhoisHost = 'whois.verisign-grs.com' }
        '.org' = @{ Provider = 'rdap'; RdapUrl = 'https://rdap.verisign.com/org/v1/domain/'; WhoisHost = 'whois.pir.org' }
        '.ua' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.ua' }
        '.com.ua' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.ua' }
        '.dp.ua' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.ua' }
        '.kiev.ua' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.ua' }
        '.wine' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.nic.wine' }
        '.pro' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.nic.pro' }
        '.cy' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.nic.cy' }
        '.bg' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.register.bg' }
        '.ae' = @{ Provider = 'whois'; RdapUrl = $null; WhoisHost = 'whois.aeda.net.ae' }
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
        [string]$WhoisHost,
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
            $asyncResult = $client.BeginConnect($WhoisHost, 43, $null, $null)
            if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                $client.Close()
                throw 'Connection timed out'
            }
            $client.EndConnect($asyncResult) | Out-Null
            $stream = $client.GetStream()
            $stream.ReadTimeout = $TimeoutMs
            $writer = New-Object System.IO.StreamWriter($stream)
            $writer.WriteLine($Domain)
            $writer.Flush()
            $builder = New-Object System.Text.StringBuilder
            $buffer = New-Object byte[] 4096
            $maxChars = 20000
            try {
                while ($builder.Length -lt $maxChars) {
                    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                    if ($bytesRead -le 0) { break }
                    $chunk = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                    [void]$builder.Append($chunk)
                }
            }
            catch {
            }
            $content = $builder.ToString()
            $writer.Dispose()
            $stream.Dispose()
            $client.Dispose()
            return $content
        }
        catch {
            if ($attempt -ge $Retries) {
                return $null
            }
        }
    }

    return $null
}

function Get-RdapData {
    <#
    .SYNOPSIS
        Queries RDAP over HTTPS for the expiration date.
    #>
    param([string]$Url)

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
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
        'Expiry Date',
        'Expiration Date',
        'Expiration Time',
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
            $value = $value -replace '[^0-9A-Za-z:\-\.T+Z /]', ''
            $value = $value.Trim()
            if ($value) {
                return $value
            }
        }
    }

    foreach ($pattern in $patterns) {
        $match = [regex]::Match($Text, '(?i)' + [regex]::Escape($pattern) + '\s+([^\r\n]+)')
        if ($match.Success) {
            $value = $match.Groups[1].Value.Trim()
            $value = $value -replace '[^0-9A-Za-z:\-\.T+Z /]', ''
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
        $json = $JsonText | ConvertFrom-Json
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

function Get-RegistrarFromText {
    <#
    .SYNOPSIS
        Extracts the registrar name from WHOIS or RDAP text.
    #>
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $patterns = @('Sponsoring Registrar', 'Registrar')
    foreach ($pattern in $patterns) {
        $match = [regex]::Match($Text, '(?im)^\s*' + [regex]::Escape($pattern) + '\s*[:=]\s*([^\r\n]+)')
        if ($match.Success) {
            $value = $match.Groups[1].Value.Trim()
            if ($value -and $value -notmatch '^whois') {
                return $value
            }
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
    $normalized = $normalized -replace '\.$', ''

    $formats = @(
        'yyyy-MM-ddTHH:mm:ssK',
        'yyyy-MM-ddTHH:mm:ss',
        'yyyy-MM-dd HH:mm:ssK',
        'yyyy-MM-dd HH:mm:ss',
        'yyyy-MM-ddTHH:mmK',
        'yyyy-MM-dd HH:mm',
        'yyyy-MM-dd',
        'yyyy.MM.dd',
        'yyyyMMdd',
        'yyyyMMddHHmmss',
        'dd-MMM-yyyy',
        'dd-MMM-yyyy HH:mm:ss',
        'dd-MMM-yyyy HH:mm',
        'dd.MM.yyyy',
        'dd.MM.yyyy HH:mm:ss',
        'dd.MM.yyyy HH:mm',
        'dd/MM/yyyy',
        'dd/MM/yyyy HH:mm:ss',
        'MM/dd/yyyy',
        'MM/dd/yyyy HH:mm:ss'
    )

    foreach ($format in $formats) {
        foreach ($cultureName in @('InvariantCulture', 'en-US', 'ru-RU')) {
            try {
                $culture = if ($cultureName -eq 'InvariantCulture') { [System.Globalization.CultureInfo]::InvariantCulture } else { New-Object System.Globalization.CultureInfo($cultureName) }
                $parsed = [datetime]::ParseExact($normalized, $format, $culture)
                return $parsed.ToUniversalTime()
            }
            catch {
            }
        }
    }

    # Try DateTimeOffset parse with a few cultures
    foreach ($cultureName in @('InvariantCulture', 'en-US', 'ru-RU')) {
        try {
            $culture = if ($cultureName -eq 'InvariantCulture') { [System.Globalization.CultureInfo]::InvariantCulture } else { New-Object System.Globalization.CultureInfo($cultureName) }
            return ([DateTimeOffset]::Parse($normalized, $culture)).ToUniversalTime().DateTime
        }
        catch {
        }
    }

    # Fallback to general DateTime parse with culture variants
    foreach ($cultureName in @('InvariantCulture', 'en-US', 'ru-RU')) {
        try {
            $culture = if ($cultureName -eq 'InvariantCulture') { [System.Globalization.CultureInfo]::InvariantCulture } else { New-Object System.Globalization.CultureInfo($cultureName) }
            return ([datetime]::Parse($normalized, $culture)).ToUniversalTime()
        }
        catch {
        }
    }

    return $null
}

function Get-ManualExpirationDate {
    <#
    .SYNOPSIS
        Converts manual override values to a UTC expiration date.
    #>
    param(
        [datetime]$ManualExpirationDate,
        [int]$ManualDaysRemaining
    )

    if ($ManualExpirationDate) {
        return $ManualExpirationDate.ToUniversalTime()
    }

    if ($PSBoundParameters.ContainsKey('ManualDaysRemaining')) {
        return ([datetime]::UtcNow).AddDays($ManualDaysRemaining)
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

function Get-StatusCode {
    <#
    .SYNOPSIS
        Maps days remaining to a numeric PRTG status code.
    #>
    param(
        [int]$DaysRemaining,
        [int]$WarningDays,
        [int]$CriticalDays
    )

    if ($DaysRemaining -le $CriticalDays) { return 2 }
    if ($DaysRemaining -le $WarningDays) { return 1 }
    return 0
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

    $code = Get-StatusCode -DaysRemaining $DaysRemaining -WarningDays $WarningDays -CriticalDays $CriticalDays
    switch ($code) {
        2 { return 'CRITICAL' }
        1 { return 'WARNING' }
        default { return 'OK' }
    }
}

function ConvertTo-XmlSafeText {
    param([string]$Text)
    if ($Text -eq $null) { return '' }
    return [System.Security.SecurityElement]::Escape($Text)
}

function Write-PrtgXml {
    <#
    .SYNOPSIS
        Writes a PRTG-compatible XML result.
    #>
    param(
        [int]$DaysRemaining,
        [datetime]$ExpirationDate,
        [string]$Registrar,
        [string]$Source,
        [string]$Status,
        [int]$StatusCode,
        [int]$WarningDays,
        [int]$CriticalDays,
        [int]$ManualDaysRemaining = 0
    )

    $timestamp = [int64]((($ExpirationDate.ToUniversalTime()) - [datetime]'1970-01-01').TotalSeconds)
    $statusText = "$Status ($DaysRemaining days remaining)"
    $text = "Domain: $Domain`n`nExpires: $($ExpirationDate.ToString('yyyy-MM-dd'))`n`nDays remaining: $DaysRemaining`n`nRegistrar: $Registrar`n`nSource: $Source"
    $escapedText = ConvertTo-XmlSafeText -Text $text
    $escapedStatus = ConvertTo-XmlSafeText -Text $statusText

    $xml = @"
<prtg>
  <result>
    <channel>Days Remaining</channel>
    <value>$DaysRemaining</value>
    <unit>Count</unit>
    <float>0</float>
    <showtime>0</showtime>
    <LimitMode>1</LimitMode>
    <LimitMaxWarning>$WarningDays</LimitMaxWarning>
    <LimitMaxError>$CriticalDays</LimitMaxError>
    <text>$escapedText</text>
  </result>
  <result>
    <channel>Days Remaining manual</channel>
    <value>$ManualDaysRemaining</value>
    <unit>Count</unit>
    <float>0</float>
    <showtime>0</showtime>
    <text>$escapedText</text>
  </result>
"@

    $xml += @"
  <result>
    <channel>Expiration Date (Unix Timestamp)</channel>
    <value>$timestamp</value>
    <unit>UnixTimestamp</unit>
    <float>0</float>
    <showtime>0</showtime>
    <text>$escapedText</text>
  </result>
  <result>
    <channel>Status Code</channel>
    <value>$StatusCode</value>
    <unit>Custom</unit>
    <float>0</float>
    <showtime>0</showtime>
    <text>$escapedStatus</text>
  </result>
  <error>0</error>
  <text>$escapedStatus</text>
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

    $escapedMessage = ConvertTo-XmlSafeText -Text $Message
    $xml = @"
<prtg>
  <error>1</error>
  <text>$escapedMessage</text>
</prtg>
"@

    Write-Output $xml
}

try {
    Write-Log -Message "Starting check for $Domain"
    $resolvedDomain = Get-RootDomain -Name $Domain
    if (-not $resolvedDomain) {
        Write-Log -Message 'Domain not found.'
        Write-PrtgError -Message 'Domain not found.'
        exit 1
    }

    $cache = Get-CacheValue -Key $resolvedDomain
    if ($cache) {
        Write-Log -Message "Using cached data for $resolvedDomain"
        $cachedManualDays = if ($cache.Source -eq 'Manual') { [int]$cache.ManualDaysRemaining } else { [int]$cache.DaysRemaining }
        Write-PrtgXml -DaysRemaining ([int]$cache.DaysRemaining) -ExpirationDate ([datetime]$cache.ExpirationDate) -Registrar $cache.Registrar -Source $cache.Source -Status $cache.Status -StatusCode ([int]$cache.StatusCode) -WarningDays $WarningDays -CriticalDays $CriticalDays -ManualDaysRemaining $cachedManualDays
        exit 0
    }

    $zoneInfo = Get-SupportedZoneInfo -Name $resolvedDomain
    if (-not $zoneInfo) {
        if ($PSBoundParameters.ContainsKey('ManualExpirationDate') -or $PSBoundParameters.ContainsKey('ManualDaysRemaining')) {
            Write-Log -Message "Unsupported zone for $resolvedDomain, using manual override"
            $manualExpiration = Get-ManualExpirationDate -ManualExpirationDate $ManualExpirationDate -ManualDaysRemaining $ManualDaysRemaining
            if ($manualExpiration) {
                $expirationDate = $manualExpiration
                $source = 'Manual'
                $registrar = 'Manual'
                $manualDaysValue = if ($PSBoundParameters.ContainsKey('ManualDaysRemaining')) { [int]$ManualDaysRemaining } else { $null }
                $daysRemaining = Get-DaysRemaining -ExpirationDate $expirationDate
                if (-not $manualDaysValue) { $manualDaysValue = $daysRemaining }
                $status = Get-Status -DaysRemaining $daysRemaining -WarningDays $WarningDays -CriticalDays $CriticalDays
                $statusCode = Get-StatusCode -DaysRemaining $daysRemaining -WarningDays $WarningDays -CriticalDays $CriticalDays
                $cachePayload = [ordered]@{
                    DaysRemaining = $daysRemaining
                    ExpirationDate = $expirationDate.ToUniversalTime().ToString('o')
                    Registrar = $registrar
                    Source = $source
                    Status = $status
                    StatusCode = $statusCode
                    ManualDaysRemaining = $manualDaysValue
                }
                Set-CacheValue -Key $resolvedDomain -Value $cachePayload
                Write-Log -Message "Resolved $resolvedDomain -> $status ($daysRemaining days) via manual override"
                Write-PrtgXml -DaysRemaining $daysRemaining -ExpirationDate $expirationDate -Registrar $registrar -Source $source -Status $status -StatusCode $statusCode -WarningDays $WarningDays -CriticalDays $CriticalDays -ManualDaysRemaining $manualDaysValue
                exit 0
            }
        }

        Write-Log -Message "Unsupported zone for $resolvedDomain"
        Write-PrtgError -Message 'Unsupported domain zone.'
        exit 1
    }

    $raw = $null
    $whoisHost = $null
    $source = $null
    $registrar = $null
    $manualDaysValue = $null

    if ($zoneInfo.Provider -eq 'rdap') {
        $rdapUrl = $zoneInfo.RdapUrl + $resolvedDomain
        $raw = Get-RdapData -Url $rdapUrl
        if ($raw) {
            $source = 'RDAP'
        }
    }

    if (-not $raw) {
        $whoisHost = $zoneInfo.WhoisHost
        $raw = Send-WhoisQuery -WhoisHost $whoisHost -Domain $resolvedDomain
        if ($raw) {
            $source = 'WHOIS'
        }
    }

    if (-not $raw) {
        Write-Log -Message "No response for $resolvedDomain"
        $snippet = '<no raw response>'
        try { if ($raw) { $snippet = $raw.Substring(0, [Math]::Min($raw.Length, 1000)) } } catch { }
        Write-Log -Message ("No response details for {0}. WhoisHost: {1}. Snippet: {2}" -f $resolvedDomain, $whoisHost, $snippet)

        if ($PSBoundParameters.ContainsKey('ManualExpirationDate') -or $PSBoundParameters.ContainsKey('ManualDaysRemaining')) {
            $manualExpiration = Get-ManualExpirationDate -ManualExpirationDate $ManualExpirationDate -ManualDaysRemaining $ManualDaysRemaining
            if ($manualExpiration) {
                Write-Log -Message "Using manual expiration override for $resolvedDomain"
                $expirationDate = $manualExpiration
                $source = 'Manual'
                $registrar = 'Manual'
                if ($PSBoundParameters.ContainsKey('ManualDaysRemaining')) {
                    $manualDaysValue = [int]$ManualDaysRemaining
                }

                $daysRemaining = Get-DaysRemaining -ExpirationDate $expirationDate
                if (-not $manualDaysValue) { $manualDaysValue = $daysRemaining }
                $status = Get-Status -DaysRemaining $daysRemaining -WarningDays $WarningDays -CriticalDays $CriticalDays
                $statusCode = Get-StatusCode -DaysRemaining $daysRemaining -WarningDays $WarningDays -CriticalDays $CriticalDays
                $cachePayload = [ordered]@{
                    DaysRemaining = $daysRemaining
                    ExpirationDate = $expirationDate.ToUniversalTime().ToString('o')
                    Registrar = $registrar
                    Source = $source
                    Status = $status
                    StatusCode = $statusCode
                    ManualDaysRemaining = $manualDaysValue
                }
                Set-CacheValue -Key $resolvedDomain -Value $cachePayload
                Write-Log -Message "Resolved $resolvedDomain -> $status ($daysRemaining days) via manual override"
                Write-PrtgXml -DaysRemaining $daysRemaining -ExpirationDate $expirationDate -Registrar $registrar -Source $source -Status $status -StatusCode $statusCode -WarningDays $WarningDays -CriticalDays $CriticalDays -ManualDaysRemaining $manualDaysValue
                exit 0
            }
        }

        Write-PrtgError -Message 'Expiration date not found.'
        exit 1
    }

    $registrar = Get-RegistrarFromText -Text $raw
    if (-not $registrar) {
        $registrar = 'Unknown'
    }

    $dateValue = Get-ExpirationDateFromText -Text $raw
    if (-not $dateValue -and $source -eq 'RDAP') {
        $dateValue = Get-RdapExpirationDate -JsonText $raw
    }

    if (-not $dateValue) {
        $referralHost = Get-ReferralHost -Text $raw
        if ($referralHost) {
            $whoisHost = $referralHost
            $raw = Send-WhoisQuery -WhoisHost $whoisHost -Domain $resolvedDomain
            $source = 'Referral WHOIS'
            $registrar = Get-RegistrarFromText -Text $raw
            $dateValue = Get-ExpirationDateFromText -Text $raw
        }
    }

    $expirationDate = $null
    if ($dateValue) {
        $expirationDate = Convert-ToDateTimeUtc -Value $dateValue
        if (-not $expirationDate) {
            $snippet = '<no raw available>'
            try { if ($raw) { $snippet = $raw.Substring(0, [Math]::Min($raw.Length, 1000)) } } catch { }
            Write-Log -Message ("Could not parse date '{0}' for {1}. Source: {2}. Registrar: {3}. WhoisHost: {4}. RawSnippet: {5}" -f $dateValue, $resolvedDomain, $source, $registrar, $whoisHost, $snippet)
        }
    }

    $manualDaysValue = $null
    if (-not $expirationDate -and ($PSBoundParameters.ContainsKey('ManualExpirationDate') -or $PSBoundParameters.ContainsKey('ManualDaysRemaining'))) {
        $manualExpiration = Get-ManualExpirationDate -ManualExpirationDate $ManualExpirationDate -ManualDaysRemaining $ManualDaysRemaining
        if ($manualExpiration) {
            Write-Log -Message "Using manual expiration override for $resolvedDomain"
            $expirationDate = $manualExpiration
            $source = 'Manual'
            $registrar = if ($registrar) { $registrar } else { 'Manual' }
            if ($PSBoundParameters.ContainsKey('ManualDaysRemaining')) {
                $manualDaysValue = [int]$ManualDaysRemaining
            }
        }
    }

    if (-not $expirationDate) {
        $snippet = '<no raw available>'
        try { if ($raw) { $snippet = $raw.Substring(0, [Math]::Min($raw.Length, 1000)) } } catch { }
        Write-Log -Message ("Expiration date not found for {0}. Source: {1}. Registrar: {2}. WhoisHost: {3}. RawSnippet: {4}" -f $resolvedDomain, $source, $registrar, $whoisHost, $snippet)
        Write-PrtgError -Message 'Expiration date not found.'
        exit 1
    }

    $daysRemaining = Get-DaysRemaining -ExpirationDate $expirationDate
    if ($source -eq 'Manual' -and -not $manualDaysValue) {
        $manualDaysValue = $daysRemaining
    }
    $status = Get-Status -DaysRemaining $daysRemaining -WarningDays $WarningDays -CriticalDays $CriticalDays
    $statusCode = Get-StatusCode -DaysRemaining $daysRemaining -WarningDays $WarningDays -CriticalDays $CriticalDays

    $cachePayload = [ordered]@{
        DaysRemaining = $daysRemaining
        ExpirationDate = $expirationDate.ToUniversalTime().ToString('o')
        Registrar = if ($registrar) { $registrar } else { 'Unknown' }
        Source = if ($source) { $source } else { 'Unknown' }
        Status = $status
        StatusCode = $statusCode
        ManualDaysRemaining = if ($manualDaysValue) { $manualDaysValue } else { 0 }
    }
    Set-CacheValue -Key $resolvedDomain -Value $cachePayload

    Write-Log -Message "Resolved $resolvedDomain -> $status ($daysRemaining days)"
    if ($manualDaysValue -eq $null) {
        $manualDaysValue = $daysRemaining
    }
    Write-PrtgXml -DaysRemaining $daysRemaining -ExpirationDate $expirationDate -Registrar $registrar -Source $source -Status $status -StatusCode $statusCode -WarningDays $WarningDays -CriticalDays $CriticalDays -ManualDaysRemaining $manualDaysValue
    exit 0
}
catch {
    try {
        $full = $_ | Out-String
        Write-Log -Message ("Exception: {0}" -f $full)
    }
    catch {
        Write-Log -Message ("Exception: {0}" -f $_.Exception.Message)
    }
    Write-PrtgError -Message 'Expiration date not found.'
    exit 1
}
