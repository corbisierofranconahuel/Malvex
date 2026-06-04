using System.Text.Encodings.Web;
using System.Text.Json;
using System.Globalization;
using Malvex.Analysis;
using Malvex.Cli;

if (!CliOptions.TryParse(args, out var options, out var parseError))
{
    Console.Error.WriteLine(parseError);
    return args.Any(a => a is "-h" or "--help" or "help")
        ? CliExitCodes.Ok
        : CliExitCodes.InvalidArguments;
}

try
{
    var fullPath = Path.GetFullPath(options.FilePath);
    if (!File.Exists(fullPath))
    {
        Console.Error.WriteLine($"No se encontro el archivo: {fullPath}");
        return CliExitCodes.TechnicalError;
    }

    var fileInfo = new FileInfo(fullPath);
    if (fileInfo.Length > options.MaxSizeBytes)
    {
        Console.Error.WriteLine($"Archivo omitido: supera el limite configurado de {options.MaxSizeBytes / 1024 / 1024} MB.");
        return CliExitCodes.TechnicalError;
    }

    var analyzer = new PeStaticAnalyzer();
    var result = analyzer.Analyze(fullPath, options.MaxStrings);
    var report = CliAnalysisMapper.FromResult(result);

    if (options.Format == "wazuh")
    {
        Console.WriteLine(ToWazuhLine(report));
    }
    else
    {
        Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            WriteIndented = options.PrettyJson,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }));
    }

    if (!result.IsPe)
    {
        return CliExitCodes.NotPe;
    }

    return report.Verdict is "suspicious" or "likely_malicious"
        ? CliExitCodes.Alert
        : CliExitCodes.Ok;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error tecnico de Malvex CLI: {ex.Message}");
    return CliExitCodes.TechnicalError;
}

static string ToWazuhLine(CliAnalysisReport report)
{
    var yara = report.Yara.Matches.Count == 0 ? "none" : string.Join(",", report.Yara.Matches);
    var findingTitles = report.Findings.Count == 0
        ? "none"
        : string.Join("|", report.Findings.Take(8).Select(f => f.Title.Replace('|', '/')));
    var confidence = report.Confidence.ToString("0.00", CultureInfo.InvariantCulture);

    return string.Join(' ', [
        "malvex",
        $"verdict={report.Verdict}",
        $"confidence={confidence}",
        $"score={report.RiskScore}",
        $"risk_level={report.RiskLevel}",
        $"is_pe={report.IsPe.ToString().ToLowerInvariant()}",
        $"sha256={report.File.Sha256}",
        $"file={Quote(report.File.Path)}",
        $"yara={Quote(yara)}",
        $"findings={Quote(findingTitles)}"
    ]);
}

static string Quote(string value)
{
    return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
}
