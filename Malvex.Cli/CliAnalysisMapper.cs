using Malvex.Core.Models;

namespace Malvex.Cli;

public static class CliAnalysisMapper
{
    public static CliAnalysisReport FromResult(PeAnalysisResult result)
    {
        var verdict = DetermineVerdict(result);
        var confidence = CalculateConfidence(result, verdict);
        var highestSeverity = GetHighestSeverity(result.Findings);

        return new CliAnalysisReport(
            Tool: "malvex",
            Version: ThisAssembly.Version,
            Verdict: verdict,
            Confidence: confidence,
            RiskScore: result.Risk.Score,
            RiskLevel: result.Risk.Level.ToString().ToLowerInvariant(),
            HighestSeverity: highestSeverity,
            IsPe: result.IsPe,
            File: new CliFileSummary(
                result.FilePath,
                result.FileName,
                result.FileSize,
                result.Sha256,
                result.Architecture,
                result.Is64Bit ? "x64" : "x86",
                $"0x{result.EntryPointRva:X}",
                $"0x{result.ImageBase:X}",
                result.CoffTimestampUtc),
            Yara: new CliYaraSummary(result.YaraAvailable, result.YaraMessage, result.YaraMatches),
            Counts: new CliAnalysisCounts(
                result.Sections.Count,
                result.Imports.Count,
                result.Imports.Sum(i => i.Functions.Count),
                result.Exports.Count,
                result.Strings.Count,
                result.Findings.Count,
                result.Disassembly.Count,
                result.CfgNodes.Count),
            Findings: result.Findings
                .Take(25)
                .Select(f => new CliFinding(f.Severity.ToString().ToLowerInvariant(), f.Title, f.Description))
                .ToList(),
            Reasons: result.Risk.Reasons.Take(20).ToList(),
            Sections: result.Sections
                .OrderByDescending(s => s.Entropy)
                .Take(12)
                .Select(s => new CliSectionSummary(s.Name, $"0x{s.VirtualAddress:X}", s.RawSize, s.Entropy, s.Characteristics))
                .ToList(),
            Guidance: result.Guidance.SuggestedActions
                .OrderBy(a => a.Priority)
                .Take(8)
                .Select(a => $"P{a.Priority}: {a.Action} - {a.Reason}")
                .ToList());
    }

    public static string DetermineVerdict(PeAnalysisResult result)
    {
        if (!result.IsPe)
        {
            return "unknown";
        }

        var hasCritical = result.Findings.Any(f => f.Severity == AnalysisSeverity.Critical);
        if (result.Risk.Score >= 80 || (hasCritical && result.Risk.Score >= 65))
        {
            return "likely_malicious";
        }

        if (result.Risk.Score >= 50 || result.YaraMatches.Count > 0 || hasCritical)
        {
            return "suspicious";
        }

        if (result.Risk.Score >= 25 || result.Findings.Any(f => f.Severity == AnalysisSeverity.Warning))
        {
            return "low_risk";
        }

        return "clean";
    }

    public static double CalculateConfidence(PeAnalysisResult result, string verdict)
    {
        if (verdict == "unknown")
        {
            return 0.15;
        }

        var baseConfidence = Math.Clamp(result.Risk.Score / 100d, 0.05, 0.95);
        var evidenceBoost = 0d;

        if (result.YaraMatches.Count > 0)
        {
            evidenceBoost += 0.12;
        }

        if (result.Findings.Any(f => f.Severity == AnalysisSeverity.Critical))
        {
            evidenceBoost += 0.15;
        }

        if (result.Findings.Count(f => f.Severity == AnalysisSeverity.Warning) >= 2)
        {
            evidenceBoost += 0.08;
        }

        if (verdict is "clean" or "low_risk")
        {
            evidenceBoost = Math.Min(evidenceBoost, 0.03);
        }

        return Math.Round(Math.Clamp(baseConfidence + evidenceBoost, 0.05, 0.99), 2);
    }

    private static string GetHighestSeverity(IReadOnlyList<HeuristicFinding> findings)
    {
        if (findings.Any(f => f.Severity == AnalysisSeverity.Critical))
        {
            return "critical";
        }

        if (findings.Any(f => f.Severity == AnalysisSeverity.Warning))
        {
            return "warning";
        }

        return findings.Any(f => f.Severity == AnalysisSeverity.Info) ? "info" : "none";
    }
}
