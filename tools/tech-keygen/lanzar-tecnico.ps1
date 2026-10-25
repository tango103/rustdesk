# Lanzador del técnico. Se guarda en el pendrive junto a tech_key.enc.
# Pide la contraseña, se la pasa SOLO al proceso de RustDesk y la borra de memoria.
$ErrorActionPreference = 'Stop'
$keyFile = Join-Path $PSScriptRoot 'tech_key.enc'
$rd = 'C:\Program Files\RustDesk\rustdesk.exe'   # ajustar al nombre/ruta de TU build
if (-not (Test-Path $keyFile)) { throw "No encuentro la llave: $keyFile (¿está el pendrive puesto?)" }
$sec  = Read-Host 'Contraseña de la llave' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
try   { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $rd
$psi.UseShellExecute = $false
$psi.EnvironmentVariables['TECH_KEY_FILE'] = $keyFile
$psi.EnvironmentVariables['TECH_KEY_PASS'] = $plain
[System.Diagnostics.Process]::Start($psi) | Out-Null
$plain = $null
