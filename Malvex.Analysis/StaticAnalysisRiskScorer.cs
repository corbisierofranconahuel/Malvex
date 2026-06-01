using Malvex.Core.Models;

namespace Malvex.Analysis;

internal static class StaticAnalysisRiskScorer
{
    public static RiskScore Build(IReadOnlyList<HeuristicFinding> findings, IReadOnlyList<string> yaraMatches)
    {
        var score = 0;
        var reasons = new List<string>();
        var strongYaraMatches = yaraMatches.Count(match =>
            !match.Contains("heuristic", StringComparison.OrdinalIgnoreCase));
        var hasCriticalYara = strongYaraMatches > 0;
        var hasCriticalFinding = findings.Any(f => f.Severity == AnalysisSeverity.Critical);
        var hasSensitiveApis = findings.Any(f => f.Title.Contains("APIs sensibles", StringComparison.OrdinalIgnoreCase));
        var hasSensitiveExports = findings.Any(f => f.Title.Contains("Exports sensibles", StringComparison.OrdinalIgnoreCase));
        var hasHighEntropy = findings.Any(f => f.Title.Contains("Entropia elevada", StringComparison.OrdinalIgnoreCase));
        var hasCommandStrings = findings.Any(f =>
            f.Title.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("shell", StringComparison.OrdinalIgnoreCase));
        var hasPersistence = findings.Any(f => f.Title.Contains("persistencia", StringComparison.OrdinalIgnoreCase));
        var hasImpact = findings.Any(f =>
            f.Title.Contains("ransomware", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("impacto", StringComparison.OrdinalIgnoreCase));

        foreach (var finding in findings)
        {
            switch (finding.Severity)
            {
                case AnalysisSeverity.Critical:
                    score += 22;
                    reasons.Add($"Critico: {finding.Title}");
                    break;
                case AnalysisSeverity.Warning:
                    score += 8;
                    reasons.Add($"Advertencia: {finding.Title}");
                    break;
            }
        }

        if (yaraMatches.Count > 0)
        {
            score += Math.Min(28, (strongYaraMatches * 10) + ((yaraMatches.Count - strongYaraMatches) * 4));
            reasons.Add($"Coincidencias YARA: {yaraMatches.Count} ({strongYaraMatches} de mayor confianza)");
        }

        if (hasSensitiveApis && hasCommandStrings)
        {
            score += 10;
            reasons.Add("Correlacion: APIs sensibles + cadenas de ejecucion.");
        }

        if (hasSensitiveApis && hasHighEntropy)
        {
            score += 10;
            reasons.Add("Correlacion: APIs sensibles + entropia elevada.");
        }

        if (hasSensitiveExports && hasPersistence)
        {
            score += 8;
            reasons.Add("Correlacion: exports relevantes + persistencia.");
        }

        if (hasImpact)
        {
            score += 15;
            reasons.Add("Correlacion: cadenas compatibles con impacto o ransomware.");
        }

        if (!hasCriticalFinding && !hasCriticalYara && hasSensitiveApis && !hasCommandStrings && !hasHighEntropy)
        {
            score = Math.Min(score, 45);
            reasons.Add("Ajuste anti-falso-positivo: APIs sensibles sin evidencia adicional.");
        }

        score = Math.Min(100, score);
        var level = score switch
        {
            >= 75 => RiskLevel.High,
            >= 40 => RiskLevel.Medium,
            _ => RiskLevel.Low
        };

        if (reasons.Count == 0)
        {
            reasons.Add("No se detectaron indicadores de riesgo significativos.");
        }

        return new RiskScore(score, level, reasons);
    }
}
