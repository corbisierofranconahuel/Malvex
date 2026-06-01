using System.Text;
using Malvex.Analysis;
using Malvex.Core.Models;

namespace Malvex.App;

internal static class AnalysisPresentationBuilder
{
    public static IReadOnlyList<string> BuildTutorialQuickStart(PeAnalysisResult? result)
    {
        var lines = new List<string>
        {
            "1. Ve a 'Resumen' y usa 'Abrir PE y analizar'.",
            "2. Revisa primero el puntaje, las secciones destacadas y los hallazgos heurísticos.",
            "3. En 'Analista Asistido', sigue las acciones sugeridas empezando por prioridad P1.",
            "4. Usa 'Desensamblado/CFG' para confirmar el flujo inicial y detectar cargadores o saltos.",
            "5. Usa 'Vista Hex' para validar bytes cerca del entrypoint o de una seccion sospechosa.",
            "6. Exporta JSON/HTML para documentar resultados y trazabilidad."
        };

        if (result is null)
        {
            lines.Add("7. Si aun no cargaste una muestra, empieza por un .exe o .dll PE valido.");
            return lines;
        }

        lines.Add($"7. Muestra actual: {result.FileName} | Riesgo {TranslateRiskLevel(result.Risk.Level)} ({result.Risk.Score}/100).");
        lines.Add(!result.YaraAvailable
            ? "8. YARA no esta disponible: revisa la instalacion local del motor antes de cerrar el analisis."
            : result.YaraMatches.Count > 0
            ? $"8. YARA detecto {result.YaraMatches.Count} regla(s): correlaciona esas coincidencias con imports, secciones y strings."
            : "8. YARA no dio coincidencias: no asumas que es limpio; revisa secciones, imports y strings antes de concluir.");
        return lines;
    }

    public static bool MatchesFindingFilter(HeuristicFinding finding, string filter)
    {
        var content = $"{finding.Title} {finding.Description}";
        return filter switch
        {
            "Criticos" => finding.Severity == AnalysisSeverity.Critical,
            "Advertencias" => finding.Severity == AnalysisSeverity.Warning,
            "Info" => finding.Severity == AnalysisSeverity.Info,
            "Inyeccion" => ContainsAny(content, "inject", "inyeccion", "WriteProcessMemory", "CreateRemoteThread"),
            "Red" => ContainsAny(content, "http", "internet", "download", "url"),
            "Persistencia" => ContainsAny(content, "registry", "regsetvalue", "hook", "startup"),
            "Anti-debug" => ContainsAny(content, "debug", "IsDebuggerPresent", "CheckRemoteDebuggerPresent"),
            _ => true
        };
    }

    public static string EstimateFindingConfidence(HeuristicFinding finding)
    {
        if (finding.Severity == AnalysisSeverity.Critical)
        {
            return "Alta";
        }

        if (finding.Severity == AnalysisSeverity.Warning)
        {
            return "Media";
        }

        return "Baja";
    }

    public static string BuildFindingTags(HeuristicFinding finding)
    {
        var content = $"{finding.Title} {finding.Description}";
        var tags = new List<string>();

        if (ContainsAny(content, "WriteProcessMemory", "CreateRemoteThread", "inyeccion"))
        {
            tags.Add("MITRE:T1055");
        }

        if (ContainsAny(content, "powershell", "cmd.exe /c"))
        {
            tags.Add("MITRE:T1059");
        }

        if (ContainsAny(content, "url", "http", "download", "InternetOpen", "HttpSendRequest"))
        {
            tags.Add("MITRE:T1105");
        }

        if (ContainsAny(content, "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "anti-debug", "debug"))
        {
            tags.Add("MITRE:T1622");
        }

        if (ContainsAny(content, "SetWindowsHookEx", "registry", "startup", "persistencia"))
        {
            tags.Add("MITRE:T1547");
        }

        return string.Join(", ", tags.Distinct(StringComparer.OrdinalIgnoreCase));
    }

    public static string BuildExecutiveSummary(PeAnalysisResult result)
    {
        var sb = new StringBuilder();
        var yaraInterpretation = BuildYaraInterpretation(result);
        sb.AppendLine("MALVEX - Resumen Ejecutivo");
        sb.AppendLine($"Archivo: {result.FileName}");
        sb.AppendLine($"Tamano: {FormatSize(result.FileSize)}");
        sb.AppendLine($"SHA256: {result.Sha256}");
        sb.AppendLine($"Arquitectura: {result.Architecture} | {(result.Is64Bit ? "x64" : "x86")}");
        sb.AppendLine($"Timestamp COFF (orientativo): {result.CoffTimestampUtc?.ToString("yyyy-MM-dd HH:mm 'UTC'") ?? "ausente/no confiable"}");
        sb.AppendLine($"Overlay fuera de secciones/certificado: {FormatSize(result.OverlaySize)}");
        sb.AppendLine($"Authenticode: {TranslateAuthenticodeStatus(result.AdvancedMetadata.Authenticode.Status)} | {result.AdvancedMetadata.Authenticode.Description}");
        sb.AppendLine($"Imphash: {(string.IsNullOrWhiteSpace(result.AdvancedMetadata.Imphash) ? "no disponible" : result.AdvancedMetadata.Imphash)}");
        sb.AppendLine($"Rich Header: {(result.AdvancedMetadata.RichHeader.IsPresent ? $"presente | Hash {result.AdvancedMetadata.RichHeader.Hash} | Entradas {result.AdvancedMetadata.RichHeader.EntryCount}" : "no detectado")}");
        sb.AppendLine($"TLS callbacks: {result.AdvancedMetadata.TlsCallbackVas.Count}");
        sb.AppendLine($"Recursos PE: {result.AdvancedMetadata.Resources.Count} entrada(s) | {result.AdvancedMetadata.ResourceTypes.Count} tipo(s) | {FormatSize(result.AdvancedMetadata.ResourceTableSize)}");
        sb.AppendLine($"PDB: {result.AdvancedMetadata.DebugPdbPath ?? "no detectada"}");
        sb.AppendLine($"Riesgo: {TranslateRiskLevel(result.Risk.Level)} ({result.Risk.Score}/100)");
        sb.AppendLine($"YARA: {(result.YaraAvailable ? (result.YaraMatches.Count > 0 ? $"{result.YaraMatches.Count} coincidencia(s)" : "sin coincidencias") : "no disponible")}");
        sb.AppendLine($"Lectura YARA: {yaraInterpretation}");
        sb.AppendLine();

        sb.AppendLine("Hallazgos principales:");
        var topFindings = result.Findings
            .OrderByDescending(f => f.Severity)
            .Take(5)
            .ToList();
        if (topFindings.Count == 0)
        {
            sb.AppendLine("- Sin hallazgos relevantes.");
        }
        else
        {
            foreach (var finding in topFindings)
            {
                var tags = BuildFindingTags(finding);
                sb.AppendLine($"- [{TranslateSeverity(finding.Severity)}] {finding.Title}{(string.IsNullOrWhiteSpace(tags) ? string.Empty : $" ({tags})")}");
            }
        }

        sb.AppendLine();
        sb.AppendLine("Acciones recomendadas:");
        var topActions = result.Guidance.SuggestedActions
            .OrderBy(a => a.Priority)
            .Take(4)
            .ToList();
        if (topActions.Count == 0)
        {
            sb.AppendLine("- Sin acciones automaticas sugeridas.");
        }
        else
        {
            foreach (var action in topActions)
            {
                sb.AppendLine($"- P{action.Priority}: {action.Action}");
            }
        }

        sb.AppendLine();
        sb.AppendLine($"Generado: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("Autor: Franco Nahuel Corbisiero");
        return sb.ToString();
    }

    public static IReadOnlyList<string> BuildQuickTriage(PeAnalysisResult result)
    {
        var yaraInterpretation = BuildYaraInterpretation(result);
        var lines = new List<string>
        {
            $"Riesgo actual: {TranslateRiskLevel(result.Risk.Level)} ({result.Risk.Score}/100)",
            $"YARA: {(result.YaraAvailable ? (result.YaraMatches.Count > 0 ? $"{result.YaraMatches.Count} coincidencias" : "sin coincidencias") : "no disponible")}",
            $"Imports: {result.Imports.Count} libs | Strings: {result.Strings.Count}",
            $"Authenticode: {TranslateAuthenticodeStatus(result.AdvancedMetadata.Authenticode.Status)} | TLS callbacks: {result.AdvancedMetadata.TlsCallbackVas.Count}",
            $"Lectura YARA: {yaraInterpretation}"
        };

        var topFindings = result.Findings
            .OrderByDescending(f => f.Severity)
            .Take(3)
            .Select(f => $"Hallazgo clave: [{TranslateSeverity(f.Severity)}] {f.Title}");
        lines.AddRange(topFindings);

        var topActions = result.Guidance.SuggestedActions
            .OrderBy(a => a.Priority)
            .Take(3)
            .Select(a => $"Accion inmediata P{a.Priority}: {a.Action}");
        lines.AddRange(topActions);

        return lines;
    }

    public static IReadOnlyList<string> BuildTimeline(PeAnalysisResult result)
    {
        var timeline = new List<string>
        {
            "1. Validar metadata PE y arquitectura.",
            "2. Revisar puntaje y razones principales del riesgo.",
            "3. Correlacionar hallazgos con YARA e imports sensibles."
        };

        if (result.Risk.Level == RiskLevel.High || result.YaraMatches.Count > 0)
        {
            timeline.Add("4. Priorizar aislamiento y validar el contexto de los indicadores criticos.");
        }
        else
        {
            timeline.Add("4. Profundizar en desensamblado y CFG para confirmar comportamiento.");
        }

        timeline.Add("5. Exportar reporte JSON/HTML para trazabilidad.");
        return timeline;
    }

    public static IReadOnlyList<string> BuildHypotheses(PeAnalysisResult result)
    {
        return result.Guidance.Hypotheses
            .Select(h => $"[{TranslateConfidence(h.Confidence)}] {h.Title} | Evidencia: {string.Join(" ; ", h.Evidence)}")
            .ToList();
    }

    public static IReadOnlyList<string> BuildChecklist(PeAnalysisResult result)
    {
        return result.Guidance.Checklist
            .Select(c => $"{(c.AutoVerified ? "[OK]" : "[PEND]")} {c.Item} - {c.Notes}")
            .ToList();
    }

    public static IReadOnlyList<string> BuildSuggestedActions(PeAnalysisResult result)
    {
        return result.Guidance.SuggestedActions
            .Select(a => $"P{a.Priority} | {a.Action} -> {a.Reason}")
            .ToList();
    }

    public static IReadOnlyList<string> BuildGuidedSteps(PeAnalysisResult result)
    {
        return result.GuidedSteps
            .Select(s => $"{s.Order}. {s.Title}: {s.Description}")
            .ToList();
    }

    public static IReadOnlyList<string> BuildFindings(PeAnalysisResult result, string filter)
    {
        return result.Findings
            .Where(f => MatchesFindingFilter(f, filter))
            .Select(f =>
            {
                var tags = BuildFindingTags(f);
                return $"[{TranslateSeverity(f.Severity)} | {EstimateFindingConfidence(f)}{(string.IsNullOrWhiteSpace(tags) ? string.Empty : $" | {tags}")}] {f.Title}: {f.Description}";
            })
            .ToList();
    }

    public static IReadOnlyDictionary<string, string> BuildTutorialSections()
    {
        return new Dictionary<string, string>
        {
            ["01 - Vision General"] =
@"Malvex es una herramienta de reversing y analisis de malware orientada a principiantes y expertos.

Objetivo:
- Reducir tiempo de triage.
- Explicar por que algo es sospechoso.
- Guiar al analista en cada paso.

Flujo recomendado:
Resumen -> Analista Asistido -> Desensamblado/CFG -> Vista Hex -> Reporte.",

            ["02 - Guia de Triage"] =
@"Flujo operativo recomendado:
1. Confirmar que la muestra sea PE valida.
2. Revisar puntaje, secciones destacadas, entropia y strings.
3. Correlacionar imports/exports con hallazgos heurísticos.
4. Interpretar YARA en contexto: coincidencia, ausencia o no disponible.
5. Solo despues validar entrypoint, desensamblado y bytes cercanos a zonas sospechosas.

Objetivo:
- Reducir tiempo de triage.
- Evitar falsos negativos por confiar solo en YARA.
- Explicar por que una muestra sube o baja de riesgo.",

            ["03 - Barra Superior"] =
@"Elementos:
- Tema: cambia la apariencia visual.
- Abrir PE y analizar: inicia analisis estatico del archivo.
- Exportar JSON/HTML: genera reporte para evidencia y trazabilidad.",

            ["04 - Resumen"] =
@"Muestra:
- Secciones PE (incluye entropia y flags).
- Imports/Exports.
- Strings destacadas.
- Hallazgos heurísticos y YARA.

Uso:
- Entropia alta puede indicar packer/ofuscacion.
- Una seccion resaltada no siempre implica malware, pero si amerita correlacion.
- Imports sensibles (WriteProcessMemory, CreateRemoteThread, etc.) elevan riesgo.",

            ["05 - Analista Asistido"] =
@"Esta pestana traduce datos tecnicos a acciones concretas:
- Hipotesis automaticas (con confianza Baja/Media/Alta).
- Lista de verificacion dinamica.
- Acciones sugeridas por prioridad.
- Razones del puntaje de riesgo.

Para principiantes:
Sigue primero acciones P1, luego P2, y valida externamente en una sandbox aislada cuando corresponda.",

            ["06 - YARA en Contexto"] =
@"Como leer YARA dentro de Malvex:
- Si hay coincidencias: no concluyas familia o malware solo por el nombre de la regla; correlaciona con secciones, imports y strings.
- Si no hay coincidencias: eso no significa que la muestra sea limpia. Puede faltar cobertura, la muestra puede estar empaquetada o la familia puede ser nueva.
- Si YARA no esta disponible: el resto del analisis estatico sigue siendo valido, pero pierde una capa de firma.

Buenas decisiones:
- Con YARA positivo + hallazgos fuertes: prioriza aislamiento y reporte.
- Con YARA negativo + secciones sospechosas/entropia alta: piensa en packer o falta de cobertura.
- Con YARA negativo + pocas señales: mantente prudente, pero no sobrerreacciones.",

            ["07 - Desensamblado y CFG"] =
@"Desensamblado:
- Vista de instrucciones del entrypoint.
- Revisa secuencias de llamadas, saltos y operaciones inusuales.

CFG:
- Grafo basico de bloques.
- Ayuda a entender flujo sin leer instruccion por instruccion.",

            ["08 - Vista Hex"] =
@"Permite inspeccionar bytes crudos por RVA.

Uso:
1. Ingresa RVA (ej: 0x401000).
2. Pulsa Cargar bytes.
3. Revisa offset/bytes/ASCII.

Ideal para validar firmas, opcodes y comparar con el desensamblado.",

            ["09 - Reportes"] =
@"Exportar JSON:
- Ideal para pipelines y procesamiento automatico.

Exportar HTML:
- Ideal para presentar hallazgos de forma legible.

Ambos incluyen:
- metadata PE
- puntaje y razones
- YARA
- hallazgos y guia",

            ["10 - Buenas Practicas"] =
@"- Analiza malware en VM/sandbox aislada.
- No ejecutes muestras desconocidas en tu host principal.
- Guarda hash y evidencia de cada analisis.
- Contrasta con otras fuentes (sandbox, TI feeds, AV reports).
- Mantiene reglas YARA y heuristicas actualizadas.",

            ["11 - Creditos"] =
@"Malvex
Creado por Franco Nahuel Corbisiero"
        };
    }

    public static string BuildYaraInterpretation(PeAnalysisResult result)
    {
        var yaraResult = new YaraScanResult(
            result.YaraAvailable,
            result.YaraMessage,
            result.YaraMatches);
        return YaraCorrelationAdvisor.BuildInterpretation(yaraResult, result.Sections, result.Findings);
    }

    public static string TranslateRiskLevel(RiskLevel level) => level switch
    {
        RiskLevel.Low => "Bajo",
        RiskLevel.Medium => "Medio",
        RiskLevel.High => "Alto",
        _ => level.ToString()
    };

    public static string TranslateSeverity(AnalysisSeverity severity) => severity switch
    {
        AnalysisSeverity.Info => "Info",
        AnalysisSeverity.Warning => "Advertencia",
        AnalysisSeverity.Critical => "Critico",
        _ => severity.ToString()
    };

    public static string TranslateConfidence(HypothesisConfidence confidence) => confidence switch
    {
        HypothesisConfidence.Low => "Baja",
        HypothesisConfidence.Medium => "Media",
        HypothesisConfidence.High => "Alta",
        _ => confidence.ToString()
    };

    public static string TranslateAuthenticodeStatus(AuthenticodeStatus status) => status switch
    {
        AuthenticodeStatus.NotPresent => "sin firma",
        AuthenticodeStatus.Valid => "valida",
        AuthenticodeStatus.PresentNotValidated => "presente, no validada localmente",
        AuthenticodeStatus.Invalid => "no validada",
        AuthenticodeStatus.Unsupported => "validacion no compatible",
        _ => "estado desconocido"
    };

    public static string FormatSize(long bytes)
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

    private static bool ContainsAny(string content, params string[] terms)
    {
        return terms.Any(t => content.Contains(t, StringComparison.OrdinalIgnoreCase));
    }
}
