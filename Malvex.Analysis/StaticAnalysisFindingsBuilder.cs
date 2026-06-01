using Malvex.Core.Models;

namespace Malvex.Analysis;

internal static class StaticAnalysisFindingsBuilder
{
    public static IReadOnlyList<HeuristicFinding> Build(
        IReadOnlyList<PeSectionInfo> sections,
        IReadOnlyList<ImportLibrary> imports,
        IReadOnlyList<ExportSymbol> exports,
        IReadOnlyList<string> strings,
        YaraScanResult yaraResult,
        long overlaySize,
        PeAdvancedMetadata advancedMetadata)
    {
        var findings = new List<HeuristicFinding>();

        var packedSections = sections.Where(SectionSignalClassifier.HasHighEntropy).ToList();
        if (packedSections.Count > 0)
        {
            var packedSectionDetails = string.Join(", ", packedSections.Select(SectionSignalClassifier.DescribeSection));
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Warning,
                "Entropia elevada",
                $"Se detectaron {packedSections.Count} secciones con entropia alta (>={SectionSignalClassifier.HighEntropyThreshold:0.0}), posible empaquetado u ofuscacion. Secciones: {packedSectionDetails}."));
        }

        var suspiciousSectionNames = sections
            .Where(SectionSignalClassifier.HasSuspiciousName)
            .Select(s => s.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (suspiciousSectionNames.Count > 0)
        {
            findings.Add(new HeuristicFinding(
                packedSections.Count > 0 ? AnalysisSeverity.Warning : AnalysisSeverity.Info,
                "Secciones sospechosas",
                $"Nombres de seccion asociados a packers: {string.Join(", ", suspiciousSectionNames)}. Confirma si estan correlacionados con entropia alta o YARA antes de elevar el riesgo."));
        }

        if (overlaySize > 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Info,
                "Datos anexados fuera de secciones",
                $"Se detectaron {FormatSize(overlaySize)} fuera de las secciones PE y de la tabla de certificados. Un overlay puede ser legitimo, pero conviene revisarlo si no era esperado."));
        }

        if (advancedMetadata.TlsCallbackVas.Count > 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Info,
                "TLS callbacks presentes",
                $"Se detectaron {advancedMetadata.TlsCallbackVas.Count} callback(s) TLS ejecutables antes del entrypoint convencional. Pueden ser legitimos, pero conviene revisarlos en muestras sospechosas."));
        }

        if (advancedMetadata.Authenticode.Status is AuthenticodeStatus.Invalid or AuthenticodeStatus.PresentNotValidated)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Info,
                "Firma Authenticode no validada",
                advancedMetadata.Authenticode.Description));
        }

        var importedFunctions = imports.SelectMany(i => i.Functions).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var suspicious = StaticAnalysisPatterns.HighRiskApis.Where(importedFunctions.Contains).ToList();
        var contextual = StaticAnalysisPatterns.ContextualApis.Where(importedFunctions.Contains).ToList();
        var commonOnly = StaticAnalysisPatterns.CommonMemoryApis.Where(importedFunctions.Contains).ToList();

        if (suspicious.Count > 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Warning,
                "APIs sensibles detectadas",
                $"Se detectaron APIs potencialmente usadas en malware: {string.Join(", ", suspicious)}."));
        }

        if (commonOnly.Count >= 3)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Info,
                "APIs de memoria comunes",
                $"Se observaron APIs comunes de memoria/carga ({string.Join(", ", commonOnly)}). Requiere correlacion para elevar riesgo."));
        }

        if (contextual.Count > 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Info,
                "APIs contextuales anti-debug",
                $"Se observaron APIs que pueden usarse para detectar depuradores ({string.Join(", ", contextual)}). Por si solas no elevan el riesgo."));
        }

        if (importedFunctions.Contains("WriteProcessMemory") && importedFunctions.Contains("CreateRemoteThread"))
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Critical,
                "Patron de inyeccion de proceso",
                "Se detecto el par WriteProcessMemory + CreateRemoteThread, patron clasico de inyeccion."));
        }

        var suspiciousExportNames = exports
            .Select(e => e.Name)
            .Where(StaticAnalysisPatterns.IsSensitiveExportName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (suspiciousExportNames.Count > 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Warning,
                "Exports sensibles detectados",
                $"Se detectaron exports potencialmente relevantes para carga lateral, servicios o reflective loading: {string.Join(", ", suspiciousExportNames)}."));
        }

        if (exports.Count > 0 && exports.Count(e => e.Name.StartsWith("ordinal_", StringComparison.OrdinalIgnoreCase)) == exports.Count)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Info,
                "Exports solo por ordinal",
                "El binario exporta funciones sin nombres simbolicos. Esto puede dificultar el analisis y merece revision manual."));
        }

        var suspiciousPowerShellStrings = strings
            .Where(s => s.Contains("powershell", StringComparison.OrdinalIgnoreCase) &&
                        StaticAnalysisPatterns.SuspiciousPowerShellTerms.Any(term => s.Contains(term, StringComparison.OrdinalIgnoreCase)))
            .Take(3)
            .ToList();
        if (suspiciousPowerShellStrings.Count > 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Warning,
                "Comando PowerShell",
                $"Se encontraron cadenas de PowerShell con indicadores de automatizacion/ocultacion: {string.Join(" | ", suspiciousPowerShellStrings)}."));
        }

        var suspiciousShellStrings = strings
            .Where(s => s.Contains("cmd.exe /c", StringComparison.OrdinalIgnoreCase) &&
                        StaticAnalysisPatterns.SuspiciousShellTerms.Any(term => s.Contains(term, StringComparison.OrdinalIgnoreCase)))
            .Take(3)
            .ToList();
        if (suspiciousShellStrings.Count > 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Warning,
                "Ejecucion por shell",
                $"Se detectaron cadenas de ejecucion via cmd.exe /c con comandos potencialmente sensibles: {string.Join(" | ", suspiciousShellStrings)}."));
        }

        var persistenceRegistryStrings = strings
            .Where(s => StaticAnalysisPatterns.PersistenceRegistryTerms.Any(term => s.Contains(term, StringComparison.OrdinalIgnoreCase)))
            .Take(3)
            .ToList();
        if (persistenceRegistryStrings.Count > 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Warning,
                "Indicador de persistencia en registro",
                $"Se detectaron cadenas asociadas a claves Run/RunOnce de Windows: {string.Join(" | ", persistenceRegistryStrings)}."));
        }

        var indirectExecutionStrings = strings
            .Where(s => StaticAnalysisPatterns.IndirectExecutionTerms.Any(term => s.Contains(term, StringComparison.OrdinalIgnoreCase)))
            .Take(3)
            .ToList();
        if (indirectExecutionStrings.Count > 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Warning,
                "Indicador de persistencia o ejecucion indirecta",
                $"Se detectaron cadenas asociadas a tareas programadas, servicios o invocacion indirecta: {string.Join(" | ", indirectExecutionStrings)}."));
        }

        var impactStrings = strings
            .Where(s => StaticAnalysisPatterns.ImpactTerms.Any(term => s.Contains(term, StringComparison.OrdinalIgnoreCase)))
            .Take(3)
            .ToList();
        if (impactStrings.Count > 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Critical,
                "Patron compatible con impacto o ransomware",
                $"Se detectaron cadenas asociadas a borrado de copias sombra o manipulacion de recuperacion: {string.Join(" | ", impactStrings)}."));
        }

        if (yaraResult.IsAvailable && yaraResult.Matches.Count > 0)
        {
            var yaraSeverity = yaraResult.Matches.Any(IsStrongYaraMatch)
                ? AnalysisSeverity.Critical
                : AnalysisSeverity.Warning;
            findings.Add(new HeuristicFinding(
                yaraSeverity,
                "YARA detecto coincidencias",
                $"{yaraResult.Message} Reglas: {string.Join(", ", yaraResult.Matches)}."));
        }
        else if (!yaraResult.IsAvailable)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Info,
                "YARA no disponible",
                yaraResult.Message));
        }

        if (findings.Count == 0)
        {
            findings.Add(new HeuristicFinding(
                AnalysisSeverity.Info,
                "Sin alertas heuristicas",
                "No se encontraron indicadores heuristicos relevantes en este analisis inicial."));
        }

        return findings;
    }

    private static bool IsStrongYaraMatch(string match)
    {
        return !match.Contains("heuristic", StringComparison.OrdinalIgnoreCase);
    }

    private static string FormatSize(long bytes)
    {
        return bytes >= 1024 * 1024
            ? $"{bytes / 1024d / 1024d:0.##} MB"
            : $"{bytes / 1024d:0.##} KB";
    }
}
