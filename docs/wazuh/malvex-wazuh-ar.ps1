param(
    [string]$MalvexCliPath,
    [string]$LogPath,
    [int]$MaxSizeMb = 256,
    [int]$MaxStrings = 300
)

$ErrorActionPreference = "Stop"

function Resolve-DefaultMalvexCliPath {
    $candidates = @(
        (Join-Path $PSScriptRoot "..\..\Malvex.Cli.exe"),
        "C:\Program Files\Malvex\Malvex.Cli.exe",
        "C:\Program Files (x86)\Malvex\Malvex.Cli.exe"
    )

    foreach ($candidate in $candidates) {
        $resolved = [System.IO.Path]::GetFullPath($candidate)
        if (Test-Path -LiteralPath $resolved -PathType Leaf) {
            return $resolved
        }
    }

    return "C:\Program Files\Malvex\Malvex.Cli.exe"
}

function Resolve-DefaultLogPath {
    $agentLog = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
    if (Test-Path -LiteralPath (Split-Path $agentLog -Parent)) {
        return $agentLog
    }

    $local = Join-Path $env:ProgramData "Malvex\wazuh-active-response.log"
    New-Item -ItemType Directory -Force (Split-Path $local -Parent) | Out-Null
    return $local
}

function Write-MalvexLog([string]$Message) {
    $timestamp = (Get-Date).ToUniversalTime().ToString("o")
    Add-Content -LiteralPath $script:ResolvedLogPath -Encoding UTF8 -Value "[$timestamp] $Message"
}

function Get-PropertyValue($Object, [string[]]$Path) {
    $current = $Object
    foreach ($segment in $Path) {
        if ($null -eq $current) { return $null }
        $property = $current.PSObject.Properties[$segment]
        if ($null -eq $property) { return $null }
        $current = $property.Value
    }

    return $current
}

function Get-CandidatePaths($Alert) {
    $paths = New-Object System.Collections.Generic.List[string]
    $knownPaths = @(
        @("parameters", "alert", "syscheck", "path"),
        @("parameters", "alert", "syscheck", "file"),
        @("parameters", "alert", "data", "path"),
        @("parameters", "alert", "data", "file"),
        @("parameters", "alert", "file"),
        @("alert", "syscheck", "path"),
        @("alert", "syscheck", "file"),
        @("alert", "data", "path"),
        @("alert", "data", "file"),
        @("syscheck", "path"),
        @("syscheck", "file"),
        @("data", "path"),
        @("data", "file")
    )

    foreach ($path in $knownPaths) {
        $value = Get-PropertyValue $Alert $path
        if ($value -is [string] -and -not [string]::IsNullOrWhiteSpace($value)) {
            $paths.Add($value)
        }
    }

    $raw = $Alert | ConvertTo-Json -Depth 32 -Compress
    $regexes = @(
        '([A-Za-z]:\\[^"''<>|]+?\.(?:exe|dll|sys|scr|ocx|cpl))',
        '([A-Za-z]:/[^"''<>|]+?\.(?:exe|dll|sys|scr|ocx|cpl))'
    )

    foreach ($regex in $regexes) {
        foreach ($match in [regex]::Matches($raw, $regex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $paths.Add($match.Groups[1].Value.Replace('\\', '\'))
        }
    }

    return $paths | Select-Object -Unique
}

if ([string]::IsNullOrWhiteSpace($MalvexCliPath)) {
    $MalvexCliPath = Resolve-DefaultMalvexCliPath
}
$script:ResolvedLogPath = if ([string]::IsNullOrWhiteSpace($LogPath)) { Resolve-DefaultLogPath } else { $LogPath }

try {
    $stdin = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($stdin)) {
        Write-MalvexLog "malvex_ar status=ignored reason=no_stdin"
        exit 0
    }

    $alert = $stdin | ConvertFrom-Json
    $candidate = Get-CandidatePaths $alert | Where-Object {
        $_ -match '\.(exe|dll|sys|scr|ocx|cpl)$' -and (Test-Path -LiteralPath $_ -PathType Leaf)
    } | Select-Object -First 1

    if ([string]::IsNullOrWhiteSpace($candidate)) {
        Write-MalvexLog "malvex_ar status=ignored reason=no_existing_pe_path"
        exit 0
    }

    if (-not (Test-Path -LiteralPath $MalvexCliPath -PathType Leaf)) {
        Write-MalvexLog "malvex_ar status=error reason=malvex_cli_missing cli=`"$MalvexCliPath`" file=`"$candidate`""
        exit 2
    }

    $arguments = @(
        "analyze",
        $candidate,
        "--wazuh",
        "--max-size-mb",
        $MaxSizeMb.ToString([System.Globalization.CultureInfo]::InvariantCulture),
        "--max-strings",
        $MaxStrings.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    )

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $MalvexCliPath @arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $line = ($output | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($line)) {
        $line = "malvex verdict=unknown confidence=0.00 score=0 risk_level=unknown is_pe=false sha256=none file=`"$candidate`" yara=`"none`" findings=`"no_output`""
    }

    Write-MalvexLog "malvex_ar status=completed exit_code=$exitCode $line"
    exit 0
}
catch {
    Write-MalvexLog "malvex_ar status=error reason=exception message=`"$($_.Exception.Message.Replace('"', ''''))`""
    exit 2
}
