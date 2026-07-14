# Installation

1. Copy the script from the src folder to your PRTG installation:
   - PRTG\Custom Sensors\EXEXML\

2. Create a new sensor of type:
   - EXE/Script Advanced

3. Configure the command line to call the script, for example:
   - powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\Check-DomainExpiration.ps1" -Domain logos-corp.com

4. Use the parameter:
   - -Domain logos-corp.com
