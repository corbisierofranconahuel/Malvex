param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$solution = Join-Path $repoRoot "Malvex.sln"
$publishMsi = Join-Path $repoRoot "scripts\publish-msi.ps1"
$distRoot = Join-Path $repoRoot "dist"
$releaseDir = Join-Path $distRoot "release"
$portableZip = Join-Path $distRoot "Malvex-win-x64-portable.zip"
$msi = Join-Path $distRoot "msi\Malvex-Setup-x64.msi"

function Assert-ChildPath([string]$Path, [string]$Parent) {
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullParent = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (!$fullPath.StartsWith($fullParent, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Ruta fuera del directorio permitido: $fullPath"
    }
}

Write-Host "[1/5] Running automated tests..."
dotnet test $solution -c $Configuration
if ($LASTEXITCODE -ne 0) { throw "Las pruebas automatizadas fallaron." }

Write-Host "[2/5] Building portable and MSI packages..."
powershell -ExecutionPolicy Bypass -File $publishMsi -Configuration $Configuration
if ($LASTEXITCODE -ne 0) { throw "La generacion del MSI fallo." }

Write-Host "[3/5] Preparing release folder..."
Assert-ChildPath $releaseDir $distRoot
if (Test-Path $releaseDir) { Remove-Item -LiteralPath $releaseDir -Recurse -Force }
New-Item -ItemType Directory -Force $releaseDir | Out-Null

$releaseFiles = @($portableZip, $msi)
foreach ($file in $releaseFiles) {
    if (!(Test-Path $file)) { throw "No se encontro el artefacto esperado: $file" }
    Copy-Item -Force $file (Join-Path $releaseDir (Split-Path $file -Leaf))
}

Write-Host "[4/5] Writing SHA256SUMS.txt..."
$checksumPath = Join-Path $releaseDir "SHA256SUMS.txt"
$checksumLines = foreach ($file in Get-ChildItem -Path $releaseDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | Sort-Object Name) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
    "$hash  $($file.Name)"
}
$checksumLines | Set-Content -LiteralPath $checksumPath -Encoding ASCII

Write-Host "[5/5] Done"
Write-Host "Release folder: $releaseDir"
Get-ChildItem -Path $releaseDir -File | Select-Object Name, Length
