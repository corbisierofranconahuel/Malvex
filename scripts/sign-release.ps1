param(
    [Parameter(Mandatory = $true)]
    [string]$PfxPath,
    [Parameter(Mandatory = $true)]
    [string]$PfxPassword,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

function Resolve-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path $kitsRoot) {
        $candidate = Get-ChildItem -Path $kitsRoot -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }

    throw "No se encontro signtool.exe. Instala Windows 10/11 SDK."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$signTool = Resolve-SignTool
$portableRoot = Join-Path $repoRoot "dist\Malvex-win-x64-portable"
$exePath = @("Malvex.App.exe", "Malvex.exe") |
    ForEach-Object { Join-Path $portableRoot $_ } |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1
$msiPath = Join-Path $repoRoot "dist\msi\Malvex-Setup-x64.msi"

if (!(Test-Path $PfxPath)) { throw "No existe el certificado PFX: $PfxPath" }
if (!$exePath) { throw "No se encontro un EXE portable para firmar en: $portableRoot" }
if (!(Test-Path $msiPath)) { throw "No existe el MSI a firmar: $msiPath" }

Write-Host "Firmando EXE..."
& $signTool sign /fd SHA256 /f $PfxPath /p $PfxPassword /tr $TimestampUrl /td SHA256 $exePath

Write-Host "Firmando MSI..."
& $signTool sign /fd SHA256 /f $PfxPath /p $PfxPassword /tr $TimestampUrl /td SHA256 $msiPath

Write-Host "Verificando firmas..."
& $signTool verify /pa /v $exePath
& $signTool verify /pa /v $msiPath

Write-Host "Firma completada."
