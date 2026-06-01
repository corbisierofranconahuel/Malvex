using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Malvex.Core.Models;

namespace Malvex.Analysis;

public sealed class ReportExporter : IReportExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public string ExportJson(PeAnalysisResult result, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        var filePath = Path.Combine(outputDirectory, BuildFileName(result, "json"));
        var json = JsonSerializer.Serialize(result, JsonOptions);
        File.WriteAllText(filePath, json, new UTF8Encoding(false));
        return filePath;
    }

    public string ExportHtml(PeAnalysisResult result, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        var filePath = Path.Combine(outputDirectory, BuildFileName(result, "html"));
        var html = BuildHtml(result);
        File.WriteAllText(filePath, html, new UTF8Encoding(false));
        return filePath;
    }

    private static string BuildFileName(PeAnalysisResult result, string extension)
    {
        var safeName = string.Concat(result.FileName.Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch));
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        return $"{safeName}_{stamp}.{extension}";
    }

    private static string BuildHtml(PeAnalysisResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!doctype html><html><head><meta charset=\"utf-8\"/>");
        sb.AppendLine("<title>Reporte Malvex</title>");
        sb.AppendLine("<style>body{font-family:Consolas,monospace;background:#0b1020;color:#d8e6ff;padding:24px;line-height:1.45}h1{color:#2bf4ba}h2{margin-top:28px;color:#b8d5ff}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;margin-bottom:18px}th,td{border:1px solid #2b3754;padding:6px;text-align:left;vertical-align:top}th{background:#16213a}.pill{display:inline-block;padding:4px 8px;border-radius:6px;background:#1b2a4a;margin:0 8px 6px 0}.card{border:1px solid #2b3754;background:#10182d;border-radius:10px;padding:14px;margin-bottom:18px}.muted{color:#9cb6e0}.empty{color:#9cb6e0;font-style:italic}@media(max-width:760px){body{padding:12px;font-size:13px}}</style>");
        sb.AppendLine("</head><body>");
        sb.AppendLine($"<h1>Reporte Malvex - {Escape(result.FileName)}</h1>");
        sb.AppendLine("<div class='card'>");
        sb.AppendLine($"<p><span class='pill'>Riesgo: {TranslateRiskLevel(result.Risk.Level)} ({result.Risk.Score}/100)</span><span class='pill'>YARA: {Escape(result.YaraMessage)}</span></p>");
        sb.AppendLine($"<p><strong>SHA256:</strong> {Escape(result.Sha256)}</p>");
        sb.AppendLine($"<p><strong>Archivo:</strong> {Escape(result.FileName)} | <strong>Tamano:</strong> {FormatSize(result.FileSize)} | <strong>Arquitectura:</strong> {Escape(result.Architecture)} {(result.Is64Bit ? "x64" : "x86")}</p>");
        sb.AppendLine($"<p><strong>Entry point RVA:</strong> 0x{result.EntryPointRva:X8} | <strong>Image base:</strong> 0x{result.ImageBase:X}</p>");
        sb.AppendLine($"<p><strong>Timestamp COFF (orientativo):</strong> {Escape(result.CoffTimestampUtc?.ToString("yyyy-MM-dd HH:mm 'UTC'") ?? "ausente/no confiable")} | <strong>Overlay fuera de secciones/certificado:</strong> {FormatSize(result.OverlaySize)}</p>");
        sb.AppendLine($"<p><strong>Cobertura:</strong> {result.Sections.Count} secciones | {result.Imports.Count} librerias importadas | {result.Exports.Count} exports | {result.Strings.Count} cadenas priorizadas</p>");
        sb.AppendLine($"<p><strong>Resumen inicial:</strong> {Escape(result.Guidance.BeginnerSummary)}</p>");
        sb.AppendLine($"<p class='muted'><strong>Lectura técnica:</strong> {Escape(result.Guidance.ExpertSummary)}</p>");
        if (result.Risk.Reasons.Count > 0)
        {
            sb.AppendLine($"<p><strong>Razones del puntaje:</strong> {Escape(string.Join(" | ", result.Risk.Reasons))}</p>");
        }

        sb.AppendLine("</div>");

        sb.AppendLine("<h2>Metadatos estaticos avanzados</h2><div class='card'>");
        sb.AppendLine($"<p><strong>Authenticode:</strong> {Escape(TranslateAuthenticodeStatus(result.AdvancedMetadata.Authenticode.Status))} | {Escape(result.AdvancedMetadata.Authenticode.Description)}</p>");
        sb.AppendLine($"<p><strong>Firmante:</strong> {Escape(result.AdvancedMetadata.Authenticode.Subject ?? "no disponible")} | <strong>Emisor:</strong> {Escape(result.AdvancedMetadata.Authenticode.Issuer ?? "no disponible")}</p>");
        sb.AppendLine($"<p><strong>Imphash:</strong> {Escape(string.IsNullOrWhiteSpace(result.AdvancedMetadata.Imphash) ? "no disponible" : result.AdvancedMetadata.Imphash)}</p>");
        sb.AppendLine($"<p><strong>Rich Header:</strong> {Escape(result.AdvancedMetadata.RichHeader.IsPresent ? $"presente | Hash {result.AdvancedMetadata.RichHeader.Hash} | Entradas {result.AdvancedMetadata.RichHeader.EntryCount} | XOR key 0x{result.AdvancedMetadata.RichHeader.XorKey:X8}" : "no detectado")}</p>");
        sb.AppendLine($"<p><strong>TLS callbacks:</strong> {result.AdvancedMetadata.TlsCallbackVas.Count} | {Escape(FormatTlsCallbacks(result.AdvancedMetadata.TlsCallbackVas))}</p>");
        sb.AppendLine($"<p><strong>Recursos PE:</strong> {FormatSize(result.AdvancedMetadata.ResourceTableSize)} | {result.AdvancedMetadata.Resources.Count} entrada(s) | {Escape(result.AdvancedMetadata.ResourceTypes.Count > 0 ? string.Join(", ", result.AdvancedMetadata.ResourceTypes) : "sin tipos detectados")}</p>");
        sb.AppendLine($"<p><strong>PDB:</strong> {Escape(result.AdvancedMetadata.DebugPdbPath ?? "no detectada")}</p>");
        sb.AppendLine($"<p><strong>Version:</strong> {Escape(result.AdvancedMetadata.FileVersion ?? "no disponible")} | <strong>Producto:</strong> {Escape(result.AdvancedMetadata.ProductName ?? "no disponible")} | <strong>Empresa:</strong> {Escape(result.AdvancedMetadata.CompanyName ?? "no disponible")}</p>");
        sb.AppendLine("</div>");

        sb.AppendLine("<h2>Inventario de recursos PE</h2><div class='table-wrap'><table><tr><th>Tipo</th><th>Nombre</th><th>Idioma</th><th>RVA</th><th>Tamano</th></tr>");
        foreach (var resource in result.AdvancedMetadata.Resources)
        {
            sb.AppendLine($"<tr><td>{Escape(resource.Type)}</td><td>{Escape(resource.Name)}</td><td>{Escape(resource.Language)}</td><td>0x{resource.DataRva:X8}</td><td>{FormatSize(resource.Size)}</td></tr>");
        }
        if (result.AdvancedMetadata.Resources.Count == 0)
        {
            sb.AppendLine("<tr><td colspan='5' class='empty'>Sin recursos PE detectados.</td></tr>");
        }
        sb.AppendLine("</table></div>");

        sb.AppendLine("<h2>Hallazgos</h2><ul>");
        foreach (var f in result.Findings)
        {
            sb.AppendLine($"<li>[{TranslateSeverity(f.Severity)}] {Escape(f.Title)} - {Escape(f.Description)}</li>");
        }
        sb.AppendLine("</ul>");

        sb.AppendLine("<h2>Secciones</h2><div class='table-wrap'><table><tr><th>Nombre</th><th>Raw Size</th><th>Entropia</th><th>Flags</th><th>Señales</th></tr>");
        foreach (var section in result.Sections)
        {
            var signals = SectionSignalClassifier.GetSignals(section);
            var signalText = signals.Count > 0 ? string.Join(" | ", signals) : "Sin señales relevantes";
            sb.AppendLine($"<tr><td>{Escape(section.Name)}</td><td>{section.RawSize}</td><td>{section.Entropy}</td><td>{Escape(section.Characteristics)}</td><td>{Escape(signalText)}</td></tr>");
        }
        sb.AppendLine("</table></div>");

        sb.AppendLine("<h2>Coincidencias YARA</h2><ul>");
        if (result.YaraMatches.Count == 0)
        {
            sb.AppendLine($"<li class='empty'>{Escape(result.YaraMessage)}</li>");
        }
        else
        {
            foreach (var y in result.YaraMatches)
            {
                sb.AppendLine($"<li>{Escape(y)}</li>");
            }
        }
        sb.AppendLine("</ul>");

        sb.AppendLine("<h2>Imports</h2><ul>");
        foreach (var library in result.Imports)
        {
            var functions = string.Join(", ", library.Functions.Take(40));
            var remainder = library.Functions.Count > 40 ? ", ..." : string.Empty;
            sb.AppendLine($"<li><strong>{Escape(library.Name)}</strong> ({library.Functions.Count}): {Escape(functions + remainder)}</li>");
        }
        if (result.Imports.Count == 0)
        {
            sb.AppendLine("<li class='empty'>Sin imports detectados.</li>");
        }
        sb.AppendLine("</ul>");

        sb.AppendLine("<h2>Exports</h2><ul>");
        foreach (var symbol in result.Exports.Take(200))
        {
            sb.AppendLine($"<li>{Escape(symbol.Name)} | ordinal {symbol.Ordinal} | RVA 0x{symbol.AddressRva:X8}</li>");
        }
        if (result.Exports.Count == 0)
        {
            sb.AppendLine("<li class='empty'>Sin exports detectados.</li>");
        }
        sb.AppendLine("</ul>");

        sb.AppendLine("<h2>Cadenas priorizadas</h2><ul>");
        foreach (var value in result.Strings.Take(120))
        {
            sb.AppendLine($"<li>{Escape(value)}</li>");
        }
        if (result.Strings.Count == 0)
        {
            sb.AppendLine("<li class='empty'>Sin cadenas imprimibles detectadas.</li>");
        }
        sb.AppendLine("</ul>");

        sb.AppendLine("<h2>Hipotesis</h2><ul>");
        foreach (var h in result.Guidance.Hypotheses)
        {
            sb.AppendLine($"<li>{Escape(h.Title)} [{TranslateConfidence(h.Confidence)}] - {Escape(string.Join(" | ", h.Evidence))}</li>");
        }
        sb.AppendLine("</ul>");

        sb.AppendLine("<h2>Acciones Sugeridas</h2><ul>");
        foreach (var a in result.Guidance.SuggestedActions)
        {
            sb.AppendLine($"<li>P{a.Priority}: {Escape(a.Action)} - {Escape(a.Reason)}</li>");
        }
        sb.AppendLine("</ul>");

        sb.AppendLine("<h2>Guia de analisis</h2><ol>");
        foreach (var step in result.GuidedSteps)
        {
            sb.AppendLine($"<li><strong>{Escape(step.Title)}</strong>: {Escape(step.Description)}</li>");
        }
        sb.AppendLine("</ol>");

        sb.AppendLine("<h2>Desensamblado del Entry Point (vista previa)</h2><div class='table-wrap'><table><tr><th>RVA</th><th>Bytes</th><th>Instruccion</th></tr>");
        foreach (var ins in result.Disassembly.Take(80))
        {
            sb.AppendLine($"<tr><td>0x{ins.Rva:X8}</td><td>{Escape(ins.Bytes)}</td><td>{Escape($"{ins.Mnemonic} {ins.Operands}".Trim())}</td></tr>");
        }
        sb.AppendLine("</table></div>");
        sb.AppendLine($"<p class='muted'>Reporte generado: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
        sb.AppendLine("<p><strong>Creado por Franco Nahuel Corbisiero</strong></p>");

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    private static string Escape(string input) =>
        System.Net.WebUtility.HtmlEncode(input ?? string.Empty);

    private static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        var size = (double)bytes;
        var unitIndex = 0;
        while (size >= 1024 && unitIndex < units.Length - 1)
        {
            size /= 1024;
            unitIndex++;
        }

        return $"{size:0.##} {units[unitIndex]}";
    }

    private static string FormatTlsCallbacks(IReadOnlyList<ulong> callbacks)
    {
        return callbacks.Count > 0
            ? string.Join(", ", callbacks.Select(address => $"0x{address:X}"))
            : "sin callbacks detectados";
    }

    private static string TranslateAuthenticodeStatus(AuthenticodeStatus status) => status switch
    {
        AuthenticodeStatus.NotPresent => "sin firma",
        AuthenticodeStatus.Valid => "valida",
        AuthenticodeStatus.PresentNotValidated => "presente, no validada localmente",
        AuthenticodeStatus.Invalid => "invalida",
        AuthenticodeStatus.Unsupported => "validacion no compatible",
        _ => "estado desconocido"
    };

    private static string TranslateRiskLevel(RiskLevel level) => level switch
    {
        RiskLevel.Low => "Bajo",
        RiskLevel.Medium => "Medio",
        RiskLevel.High => "Alto",
        _ => level.ToString()
    };

    private static string TranslateSeverity(AnalysisSeverity severity) => severity switch
    {
        AnalysisSeverity.Info => "Info",
        AnalysisSeverity.Warning => "Advertencia",
        AnalysisSeverity.Critical => "Critico",
        _ => severity.ToString()
    };

    private static string TranslateConfidence(HypothesisConfidence confidence) => confidence switch
    {
        HypothesisConfidence.Low => "Baja",
        HypothesisConfidence.Medium => "Media",
        HypothesisConfidence.High => "Alta",
        _ => confidence.ToString()
    };
}
