param(
    [string]$Runtime = "win-x64",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$project = Join-Path $repoRoot "Malvex.App\Malvex.App.csproj"
$cliProject = Join-Path $repoRoot "Malvex.Cli\Malvex.Cli.csproj"
$distRoot = Join-Path $repoRoot "dist"
$packageName = "Malvex-$Runtime-portable"
$packageDir = Join-Path $distRoot $packageName
$zipPath = Join-Path $distRoot "$packageName.zip"
$tempPublish = Join-Path $repoRoot "Malvex.App\bin\$Configuration\net8.0-windows\$Runtime\publish"
$cliTempPublish = Join-Path $repoRoot "Malvex.Cli\bin\$Configuration\net8.0\$Runtime\publish"

function Assert-ChildPath([string]$Path, [string]$Parent) {
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullParent = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (!$fullPath.StartsWith($fullParent, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Ruta fuera del directorio permitido: $fullPath"
    }
}

Write-Host "[1/5] Cleaning old package output..."
Assert-ChildPath $packageDir $distRoot
Assert-ChildPath $tempPublish (Join-Path $repoRoot "Malvex.App\bin")
Assert-ChildPath $cliTempPublish (Join-Path $repoRoot "Malvex.Cli\bin")
if (Test-Path $packageDir) { Remove-Item -LiteralPath $packageDir -Recurse -Force }
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
if (Test-Path $tempPublish) { Remove-Item -LiteralPath $tempPublish -Recurse -Force }
if (Test-Path $cliTempPublish) { Remove-Item -LiteralPath $cliTempPublish -Recurse -Force }
New-Item -ItemType Directory -Force $distRoot | Out-Null

Write-Host "[2/5] Publishing self-contained single-file executables..."
dotnet publish $project -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:IncludeAllContentForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false
if ($LASTEXITCODE -ne 0) { throw "dotnet publish fallo con codigo $LASTEXITCODE." }
dotnet publish $cliProject -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false
if ($LASTEXITCODE -ne 0) { throw "dotnet publish CLI fallo con codigo $LASTEXITCODE." }

Write-Host "[3/5] Copying publish output and runtime assets..."
Copy-Item -Recurse -Force $tempPublish $packageDir
Copy-Item -Force (Join-Path $cliTempPublish "Malvex.Cli.exe") (Join-Path $packageDir "Malvex.Cli.exe")

$rulesSource = Join-Path $repoRoot "rules"
$toolsSource = Join-Path $repoRoot "tools"
$docsSource = Join-Path $repoRoot "docs"
$publicFiles = @(
    "README.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "SECURITY.md",
    "PRIVACY.md",
    "CHANGELOG.md"
)

if (Test-Path $rulesSource) { Copy-Item -Recurse -Force $rulesSource (Join-Path $packageDir "rules") }
if (Test-Path $toolsSource) { Copy-Item -Recurse -Force $toolsSource (Join-Path $packageDir "tools") }
if (Test-Path $docsSource) { Copy-Item -Recurse -Force $docsSource (Join-Path $packageDir "docs") }
foreach ($fileName in $publicFiles) {
    $source = Join-Path $repoRoot $fileName
    if (Test-Path $source) { Copy-Item -Force $source (Join-Path $packageDir $fileName) }
}
Get-ChildItem -Path $packageDir -Filter ".gitkeep" -Recurse -File |
    Remove-Item -Force

# Resolve executable name from packaged files (handles Malvex.exe vs Malvex.App.exe)
$exeCandidates = @("Malvex.App.exe", "Malvex.exe")
$mainExe = $null
foreach ($candidate in $exeCandidates) {
    if (Test-Path (Join-Path $packageDir $candidate)) {
        $mainExe = $candidate
        break
    }
}
if (-not $mainExe) {
    $discovered = Get-ChildItem -Path $packageDir -Filter "*.exe" | Select-Object -First 1
    if ($null -eq $discovered) {
        throw "No se encontro ningun .exe en el paquete portable."
    }
    $mainExe = $discovered.Name
}

$launcherPath = Join-Path $packageDir "Run-Malvex.cmd"
@"
@echo off
setlocal
cd /d %~dp0
set "APP_EXE=$mainExe"
if not exist "%~dp0%APP_EXE%" (
  echo [ERROR] No se encontro %APP_EXE% en esta carpeta.
  echo Asegurate de extraer TODO el .zip antes de ejecutar.
  pause
  exit /b 1
)
start "" "%~dp0%APP_EXE%"
"@ | Set-Content -Encoding ASCII $launcherPath

$quickStartPath = Join-Path $packageDir "QUICKSTART.txt"
@"
Paquete portable de Malvex

1) Extrae TODO el .zip a una carpeta local (no ejecutar desde dentro del .zip)
2) Ejecuta Run-Malvex.cmd o $mainExe
3) Si SmartScreen bloquea: click en 'Mas informacion' -> 'Ejecutar de todas formas'
4) Para YARA, esta carpeta ya incluye rules/ y tools/yara/
5) Para automatizacion/SIEM ejecuta: Malvex.Cli.exe analyze "C:\ruta\archivo.exe" --json
6) Para Wazuh o logs compactos ejecuta: Malvex.Cli.exe analyze "C:\ruta\archivo.exe" --wazuh
7) Si YARA no esta disponible en una VM limpia, instala Microsoft Visual C++ Redistributable x64

Creado por Franco Nahuel Corbisiero
"@ | Set-Content -Encoding UTF8 $quickStartPath

Write-Host "[4/5] Creating zip archive..."
Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $zipPath -CompressionLevel Optimal

Write-Host "[5/5] Done"
Write-Host "Portable folder: $packageDir"
Write-Host "Zip package:     $zipPath"
