# PRTG Domain Expiration Sensor

## English

This repository contains a PowerShell-based sensor for PRTG Network Monitor that checks the expiration date of domain names without using commercial APIs or third-party executables. The implementation relies only on built-in PowerShell, .NET, TCP sockets, HTTP(S), RDAP, and WHOIS.

### Project purpose

The sensor accepts a domain name such as `example-domain.com` and returns the number of days remaining until expiration in a format understood by PRTG.

### Key functions

- `Write-Log`: writes timestamped log entries when `-EnableLogging` is enabled.
- `Get-CacheFilePath`, `Get-CacheValue`, `Set-CacheValue`: manage local JSON caching of results.
- `Get-RootDomain`: normalizes input and extracts the registered domain, including special domain suffix handling.
- `Get-SupportedZoneInfo`: maps supported zones to RDAP or WHOIS providers.
- `Send-WhoisQuery`: queries WHOIS servers over TCP port 43 and returns raw response text.
- `Get-RdapData`: fetches RDAP JSON data over HTTPS.
- `Get-ExpirationDateFromText`: extracts expiration date strings from WHOIS or RDAP text.
- `Get-RdapExpirationDate`: parses expiration events from RDAP JSON.
- `Get-ReferralHost`: detects referral WHOIS servers from raw response text.
- `Get-RegistrarFromText`: extracts registrar information from raw data.
- `Convert-ToDateTimeUtc`: converts date strings into UTC DateTime values.
- `Get-ManualExpirationDate`: builds expiration date from manual input when automatic lookup fails.
- `Get-DaysRemaining`, `Get-StatusCode`, `Get-Status`: compute remaining days and PRTG status values.
- `ConvertTo-XmlSafeText`: escapes text for safe XML output.
- `Write-PrtgXml`: generates PRTG-compatible XML results, including channels: `Days Remaining`, `Days Remaining manual`, `Expiration Date (Unix Timestamp)`, and `Status Code`.
- `Write-PrtgError`: emits error XML when expiration cannot be determined.

### Supported domains

- Version 1.0: `.com`, `.net`, `.org`
- Version 1.1: `.ua`, `.com.ua`, `.dp.ua`, `.kiyv.ua`
- Version 1.2: `.pro`, `.wine`, `.cy`, `.bg`, `.ae`

### Installation

1. Copy [src/Check-DomainExpiration.ps1](src/Check-DomainExpiration.ps1) to the PRTG Custom Sensors EXEXML folder.
2. Create a new sensor of type EXE/Script Advanced.
3. Configure the command line:
   - `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\Check-DomainExpiration.ps1" -Domain example-domain.com`

### Usage

Run the script locally or from PRTG with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Check-DomainExpiration.ps1 -Domain example-domain.com
```

Run with manual expiration values when WHOIS/RDAP cannot resolve the date:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Check-DomainExpiration.ps1 -Domain example-domain.com -ManualExpirationDate 2026-12-31
```

or:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Check-DomainExpiration.ps1 -Domain example-domain.com -ManualDaysRemaining 120
```

### Example XML output

```xml
<prtg>
  <result>
    <channel>Days Remaining</channel>
    <value>274</value>
    <unit>Count</unit>
    <float>0</float>
    <showtime>0</showtime>
    <text>Domain: example-domain.com

Expires: 2027-04-04

Registrar: Unknown

RDAP</text>
  </result>
  <error>0</error>
  <summary>OK</summary>
</prtg>
```

### Updating

Pull the latest version from this repository and replace the script in the PRTG EXEXML folder.

### Notes

- RDAP is used first when available.
- WHOIS over TCP port 43 is used as a fallback.
- If the expiration date cannot be determined automatically, you can supply `-ManualExpirationDate` or `-ManualDaysRemaining`.
- If no date can be determined or entered manually, the script returns XML with `<error>1</error>` and the summary `Expiration date not found.`

### Testing

Example test scripts are available in [tests](tests) for common zones such as `.com`, `.ua`, `.dp.ua`, and `.wine`.

## Українською

Цей репозиторій містить сенсор для PRTG Network Monitor на PowerShell, який перевіряє дату завершення реєстрації доменів без використання комерційних API або сторонніх виконуваних файлів. Реалізація використовує лише вбудований PowerShell, .NET, TCP-сокети, HTTP(S), RDAP та WHOIS.

### Мета проекту

Сенсор отримує назву домену, наприклад `example-domain.com`, і повертає кількість днів, що залишилися до закінчення реєстрації, у форматі, сумісному з PRTG.

### Основні функції

- `Write-Log`: записує логи з мітками часу, коли ввімкнено `-EnableLogging`.
- `Get-CacheFilePath`, `Get-CacheValue`, `Set-CacheValue`: керують локальним кешем у форматі JSON.
- `Get-RootDomain`: нормалізує введення та визначає зареєстрований домен, включно зі спеціальними суфіксами.
- `Get-SupportedZoneInfo`: зіставляє підтримувані зони з RDAP або WHOIS провайдерами.
- `Send-WhoisQuery`: виконує WHOIS-запити через TCP-порт 43 та повертає сирий текст.
- `Get-RdapData`: отримує RDAP JSON через HTTPS.
- `Get-ExpirationDateFromText`: витягує дату закінчення з WHOIS або RDAP тексту.
- `Get-RdapExpirationDate`: розбирає дату закінчення з RDAP JSON.
- `Get-ReferralHost`: визначає реферальний WHOIS-сервер з відповіді.
- `Get-RegistrarFromText`: витягує інформацію про реєстратора з сирих даних.
- `Convert-ToDateTimeUtc`: перетворює рядки дат у UTC DateTime.
- `Get-ManualExpirationDate`: формує дату закінчення з ручного вводу, якщо автоматичний пошук не спрацював.
- `Get-DaysRemaining`, `Get-StatusCode`, `Get-Status`: обчислюють залишок днів і статус для PRTG.
- `ConvertTo-XmlSafeText`: екранує текст для безпечного XML-виводу.
- `Write-PrtgXml`: генерує XML-результат для PRTG з каналами `Days Remaining`, `Days Remaining manual`, `Expiration Date (Unix Timestamp)` та `Status Code`.
- `Write-PrtgError`: повертає XML помилки, якщо дату не вдалося знайти.

### Підтримувані домени

- Версія 1.0: `.com`, `.net`, `.org`
- Версія 1.1: `.ua`, `.com.ua`, `.dp.ua`, `.kiyv.ua`
- Версія 1.2: `.pro`, `.wine`, `.cy`, `.bg`, `.ae`

### Встановлення

1. Скопіюйте [src/Check-DomainExpiration.ps1](src/Check-DomainExpiration.ps1) у папку PRTG Custom Sensors EXEXML.
2. Створіть новий сенсор типу EXE/Script Advanced.
3. Налаштуйте командний рядок:
   - `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\Check-DomainExpiration.ps1" -Domain example-domain.com`

### Використання

Запустіть скрипт локально або з PRTG так:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Check-DomainExpiration.ps1 -Domain example-domain.com
```

### Приклад XML-виводу

```xml
<prtg>
  <result>
    <channel>Days Remaining</channel>
    <value>274</value>
    <unit>Count</unit>
    <float>0</float>
    <showtime>0</showtime>
    <text>Domain: example-domain.com

Expires: 2027-04-04

Registrar: Unknown

RDAP</text>
  </result>
  <error>0</error>
  <summary>OK</summary>
</prtg>
```

### Оновлення

Оновіть репозиторій до останньої версії та замініть скрипт у папці PRTG EXEXML.

### Примітки

- Спочатку використовується RDAP, якщо він доступний.
- WHOIS через TCP-порт 43 використовується як резервний варіант.
- Якщо дату закінчення не вдалося визначити, скрипт повертає XML з `<error>1</error>` і текстом `Expiration date not found.`

### Тестування

Приклади тестових скриптів доступні у [tests](tests) для типових зон, таких як `.com`, `.ua`, `.dp.ua` та `.wine`.
