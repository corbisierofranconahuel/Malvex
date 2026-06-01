using System.Diagnostics;

namespace Malvex.Analysis;

public sealed class YaraCliScanner : IYaraScanner
{
    private const int ScanTimeoutMilliseconds = 15_000;
    private readonly string _rulesDirectory;
    private readonly string _rulesLookupInfo;

    public YaraCliScanner(string? rulesDirectory = null)
    {
        var resolved = rulesDirectory is null
            ? ResolveRulesDirectoryWithDiagnostics()
            : (rulesDirectory, $"manual:{rulesDirectory}");
        _rulesDirectory = resolved.Item1;
        _rulesLookupInfo = resolved.Item2;
    }

    public YaraScanResult Scan(string targetFilePath)
    {
        if (!Directory.Exists(_rulesDirectory))
        {
            return new YaraScanResult(false, $"No se encontro la carpeta rules para YARA. ({_rulesLookupInfo})", []);
        }

        var ruleFiles = Directory
            .EnumerateFiles(_rulesDirectory, "*.yar", SearchOption.AllDirectories)
            .Concat(Directory.EnumerateFiles(_rulesDirectory, "*.yara", SearchOption.AllDirectories))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (ruleFiles.Count == 0)
        {
            return new YaraScanResult(false, "No hay reglas .yar/.yara en la carpeta rules.", []);
        }

        var yaraExecutableResolution = ResolveYaraExecutableWithDiagnostics();
        var yaraExecutable = yaraExecutableResolution.path;
        if (string.IsNullOrWhiteSpace(yaraExecutable))
        {
            return new YaraScanResult(false, $"No se encontro yara.exe/yara64.exe. ({yaraExecutableResolution.lookupInfo})", []);
        }

        var args = BuildArguments(ruleFiles, targetFilePath);
        var startInfo = new ProcessStartInfo
        {
            FileName = yaraExecutable,
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return new YaraScanResult(false, "No se pudo iniciar el proceso YARA.", []);
            }

            var stdOutTask = process.StandardOutput.ReadToEndAsync();
            var stdErrTask = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(ScanTimeoutMilliseconds))
            {
                TryTerminate(process);
                return new YaraScanResult(
                    false,
                    $"YARA excedio el tiempo limite de {ScanTimeoutMilliseconds / 1000} segundos. Revisa las reglas o ejecuta yara64.exe manualmente para diagnosticar el bloqueo.",
                    []);
            }

            Task.WaitAll(stdOutTask, stdErrTask);
            var stdOut = stdOutTask.Result;
            var stdErr = stdErrTask.Result;

            if (process.ExitCode != 0 && string.IsNullOrWhiteSpace(stdOut))
            {
                var error = BuildExecutionError(process.ExitCode, stdErr);
                return new YaraScanResult(false, $"YARA devolvio error: {error}", []);
            }

            var matches = ParseMatches(stdOut);
            var message = matches.Count > 0
                ? $"YARA detecto {matches.Count} regla(s)."
                : "YARA ejecutado sin coincidencias.";

            return new YaraScanResult(true, message, matches);
        }
        catch (Exception ex)
        {
            return new YaraScanResult(false, $"No se pudo iniciar YARA en '{yaraExecutable}': {ex.Message}", []);
        }
    }

    private static string BuildExecutionError(int exitCode, string standardError)
    {
        var error = standardError.Trim();
        if (string.IsNullOrWhiteSpace(error))
        {
            return $"codigo de salida {exitCode}, sin detalle. Verifica que el runtime de Visual C++ este instalado y ejecuta yara64.exe manualmente para diagnosticar dependencias faltantes.";
        }

        if (error.Contains("non-ascii character", StringComparison.OrdinalIgnoreCase))
        {
            error += " | Sugerencia: guarda las reglas .yar en UTF-8 sin BOM o ASCII.";
        }

        return error;
    }

    private static void TryTerminate(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch
        {
            // The process may have exited between timeout detection and termination.
        }
    }

    private static string BuildArguments(IReadOnlyList<string> ruleFiles, string targetFilePath)
    {
        var quotedRules = string.Join(" ", ruleFiles.Select(Quote));
        return $"{quotedRules} {Quote(targetFilePath)}";
    }

    private static IReadOnlyList<string> ParseMatches(string output)
    {
        var matches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var lines = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            // YARA output format: <rule_name> <scanned_file>
            var firstToken = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(firstToken))
            {
                matches.Add(firstToken.Trim());
            }
        }

        return matches.OrderBy(m => m, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string Quote(string value) => $"\"{value}\"";

    private static (string path, string lookupInfo) ResolveRulesDirectoryWithDiagnostics()
    {
        var checkedPaths = new List<string>();

        var exeDir = GetExecutableDirectory();
        if (!string.IsNullOrWhiteSpace(exeDir))
        {
            var fromExe = FindRulesInAncestors(exeDir, checkedPaths);
            if (!string.IsNullOrWhiteSpace(fromExe))
            {
                return (fromExe, $"resolved-from-exe:{fromExe}");
            }
        }

        var fromBase = FindRulesInAncestors(AppContext.BaseDirectory, checkedPaths);
        if (!string.IsNullOrWhiteSpace(fromBase))
        {
            return (fromBase, $"resolved-from-base:{fromBase}");
        }

        var fromCwd = FindRulesInAncestors(Directory.GetCurrentDirectory(), checkedPaths);
        if (!string.IsNullOrWhiteSpace(fromCwd))
        {
            return (fromCwd, $"resolved-from-cwd:{fromCwd}");
        }

        var fallback = Path.Combine(AppContext.BaseDirectory, "rules");
        checkedPaths.Add(fallback);
        return (fallback, $"fallback:{fallback};checked:{string.Join(" | ", checkedPaths)}");
    }

    private static string? FindRulesInAncestors(string startPath, List<string>? checkedPaths = null)
    {
        var current = new DirectoryInfo(startPath);
        while (current is not null)
        {
            var candidate = Path.Combine(current.FullName, "rules");
            checkedPaths?.Add(candidate);
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        return null;
    }

    private static (string? path, string lookupInfo) ResolveYaraExecutableWithDiagnostics()
    {
        var checkedPaths = new List<string>();

        var exeDir = GetExecutableDirectory();
        if (!string.IsNullOrWhiteSpace(exeDir))
        {
            var fromExe = FindExecutableInAncestors(exeDir, checkedPaths);
            if (!string.IsNullOrWhiteSpace(fromExe))
            {
                return (fromExe, $"resolved-from-exe:{fromExe}");
            }
        }

        var fromBase = FindExecutableInAncestors(AppContext.BaseDirectory, checkedPaths);
        if (!string.IsNullOrWhiteSpace(fromBase))
        {
            return (fromBase, $"resolved-from-base:{fromBase}");
        }

        var fromCurrent = FindExecutableInAncestors(Directory.GetCurrentDirectory(), checkedPaths);
        if (!string.IsNullOrWhiteSpace(fromCurrent))
        {
            return (fromCurrent, $"resolved-from-cwd:{fromCurrent}");
        }

        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var path in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var yara64 = Path.Combine(path.Trim(), "yara64.exe");
            checkedPaths.Add(yara64);
            if (File.Exists(yara64))
            {
                return (yara64, $"resolved-from-PATH:{yara64}");
            }

            var yara = Path.Combine(path.Trim(), "yara.exe");
            checkedPaths.Add(yara);
            if (File.Exists(yara))
            {
                return (yara, $"resolved-from-PATH:{yara}");
            }
        }

        return (null, $"checked:{string.Join(" | ", checkedPaths)}");
    }

    private static string? GetExecutableDirectory()
    {
        try
        {
            var modulePath = Process.GetCurrentProcess().MainModule?.FileName;
            return string.IsNullOrWhiteSpace(modulePath) ? null : Path.GetDirectoryName(modulePath);
        }
        catch
        {
            return null;
        }
    }

    private static string? FindExecutableInAncestors(string startPath, List<string>? checkedPaths = null)
    {
        var current = new DirectoryInfo(startPath);
        while (current is not null)
        {
            var yara64 = Path.Combine(current.FullName, "tools", "yara", "yara64.exe");
            checkedPaths?.Add(yara64);
            if (File.Exists(yara64))
            {
                return yara64;
            }

            var yara = Path.Combine(current.FullName, "tools", "yara", "yara.exe");
            checkedPaths?.Add(yara);
            if (File.Exists(yara))
            {
                return yara;
            }

            current = current.Parent;
        }

        return null;
    }
}
