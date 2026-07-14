# PRTG Domain Expiration Sensor

This repository contains a PowerShell-based sensor for PRTG Network Monitor that checks the expiration date of domain names without using commercial APIs or third-party executables. The implementation relies only on built-in PowerShell, .NET, TCP sockets, HTTP(S), RDAP, and WHOIS.

## Project purpose

The sensor accepts a domain name such as `logos-corp.com` and returns the number of days remaining until expiration in a format understood by PRTG.

## Supported domains

- Version 1.0: `.com`, `.net`, `.org`
- Version 1.1: `.ua`, `.com.ua`, `.dp.ua`, `.kiyv.ua`
- Version 1.2: `.pro`, `.wine`, `.cy`, `.bg`, `.ae`

## Installation

1. Copy [src/Check-DomainExpiration.ps1](src/Check-DomainExpiration.ps1) to the PRTG Custom Sensors EXEXML folder.
2. Create a new sensor of type EXE/Script Advanced.
3. Configure the command line:
   - `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\Check-DomainExpiration.ps1" -Domain logos-corp.com`

## Usage

Run the script locally or from PRTG with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Check-DomainExpiration.ps1 -Domain logos-corp.com
```

## Example XML output

```xml
<prtg>
  <result>
    <channel>Days Remaining</channel>
    <value>274</value>
    <unit>Count</unit>
    <float>0</float>
    <showtime>0</showtime>
    <text>Domain: logos-corp.com

Expires: 2027-04-04

Registrar: Unknown

RDAP</text>
  </result>
  <error>0</error>
  <summary>OK</summary>
</prtg>
```

## Updating

Pull the latest version from this repository and replace the script in the PRTG EXEXML folder.

## Notes

- RDAP is used first when available.
- WHOIS over TCP port 43 is used as a fallback.
- If the expiration date cannot be determined, the script returns XML with `<error>1</error>` and the summary `Expiration date not found.`

## Testing

Example test scripts are available in [tests](tests) for common zones such as `.com`, `.ua`, `.dp.ua`, and `.wine`.
