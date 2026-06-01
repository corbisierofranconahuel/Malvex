using Malvex.Core.Models;

namespace Malvex.Analysis;

public static class YaraCorrelationAdvisor
{
    public static string BuildInterpretation(
        YaraScanResult yaraResult,
        IReadOnlyList<PeSectionInfo> sections,
        IReadOnlyList<HeuristicFinding> findings)
    {
        if (!yaraResult.IsAvailable)
        {
            return $"YARA no disponible. {yaraResult.Message}";
        }

        if (yaraResult.Matches.Count > 0)
        {
            return $"YARA detecto {yaraResult.Matches.Count} regla(s): {string.Join(", ", yaraResult.Matches)}. Correlaciona estas reglas con las secciones, imports y hallazgos antes de concluir familia o capacidad.";
        }

        var highEntropySections = sections
            .Where(SectionSignalClassifier.HasHighEntropy)
            .Select(s => s.Name)
            .ToList();
        var suspiciousSectionNames = sections
            .Where(SectionSignalClassifier.HasSuspiciousName)
            .Select(s => s.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var criticalOrWarningFindings = findings.Count(f => f.Severity is AnalysisSeverity.Critical or AnalysisSeverity.Warning);

        if (highEntropySections.Count > 0 || suspiciousSectionNames.Count > 0 || criticalOrWarningFindings >= 2)
        {
            var evidence = new List<string>();
            if (highEntropySections.Count > 0)
            {
                evidence.Add($"entropia alta en {string.Join(", ", highEntropySections)}");
            }

            if (suspiciousSectionNames.Count > 0)
            {
                evidence.Add($"nombres de seccion sospechosos: {string.Join(", ", suspiciousSectionNames)}");
            }

            if (criticalOrWarningFindings >= 2)
            {
                evidence.Add($"{criticalOrWarningFindings} hallazgos estaticos relevantes");
            }

            return $"YARA se ejecuto sin coincidencias, pero siguen presentes señales estaticas ({string.Join(" | ", evidence)}). Esto suele indicar cobertura insuficiente, muestra empaquetada o una familia no contemplada por las reglas actuales.";
        }

        return "YARA se ejecuto sin coincidencias. Eso reduce evidencia por firmas, pero no demuestra que la muestra sea benigna por si sola.";
    }
}
