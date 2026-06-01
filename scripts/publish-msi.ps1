param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$portableScript = Join-Path $repoRoot "scripts\publish-portable.ps1"
$installerProject = Join-Path $repoRoot "Malvex.Installer\Malvex.Installer.wixproj"
$distRoot = Join-Path $repoRoot "dist"
$msiOutDir = Join-Path $distRoot "msi"
$msiFile = Join-Path $msiOutDir "Malvex-Setup-x64.msi"

function Assert-ChildPath([string]$Path, [string]$Parent) {
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullParent = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (!$fullPath.StartsWith($fullParent, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Ruta fuera del directorio permitido: $fullPath"
    }
}

Write-Host "[1/3] Building portable package..."
powershell -ExecutionPolicy Bypass -File $portableScript
if ($LASTEXITCODE -ne 0) { throw "La generacion del portable fallo con codigo $LASTEXITCODE." }

Write-Host "[2/3] Building MSI installer..."
Assert-ChildPath $msiOutDir $distRoot
if (Test-Path $msiOutDir) { Remove-Item -LiteralPath $msiOutDir -Recurse -Force }
New-Item -ItemType Directory -Force $msiOutDir | Out-Null

dotnet build $installerProject -c $Configuration -o $msiOutDir
if ($LASTEXITCODE -ne 0) { throw "La compilacion del MSI fallo con codigo $LASTEXITCODE." }

$generatedMsi = Get-ChildItem -Path $msiOutDir -Filter "*.msi" | Select-Object -First 1
if ($null -eq $generatedMsi) {
    throw "No se genero ningun archivo MSI."
}

if ($generatedMsi.FullName -ne $msiFile) {
    if (Test-Path $msiFile) { Remove-Item -Force $msiFile }
    Move-Item -Force $generatedMsi.FullName $msiFile
}

Write-Host "[3/3] Done"
Write-Host "MSI package: $msiFile"
