using Malvex.Analysis;
using Malvex.Cli;
using Malvex.Core.Models;

namespace Malvex.Tests;

public sealed class CliContractTests
{
    [Fact]
    public void Mapper_ForBenignAnalyzerAssembly_ReturnsStableJsonContract()
    {
        var target = typeof(PeStaticAnalyzer).Assembly.Location;

        var result = CreateAnalyzer().Analyze(target);
        var report = CliAnalysisMapper.FromResult(result);

        Assert.Equal("malvex", report.Tool);
        Assert.Equal("1.1.0", report.Version);
        Assert.True(report.IsPe);
        Assert.Equal(64, report.File.Sha256.Length);
        Assert.InRange(report.Confidence, 0.05, 0.99);
        Assert.NotEmpty(report.Sections);
        Assert.True(report.Counts.Sections > 0);
        Assert.Contains(report.Verdict, ["clean", "low_risk", "suspicious", "likely_malicious"]);
    }

    [Fact]
    public void Mapper_ForNonPeResult_ReturnsUnknownVerdict()
    {
        var path = Path.Combine(Path.GetTempPath(), $"malvex-cli-invalid-{Guid.NewGuid():N}.bin");
        try
        {
            File.WriteAllBytes(path, [0x4D, 0x5A, 0x00, 0x01, 0x02, 0x03]);

            var result = CreateAnalyzer().Analyze(path);
            var report = CliAnalysisMapper.FromResult(result);

            Assert.False(report.IsPe);
            Assert.Equal("unknown", report.Verdict);
            Assert.Equal(0.15, report.Confidence);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void DetermineVerdict_UsesRiskAndYaraCorrelation()
    {
        var low = BuildResult(score: 10, matches: []);
        var yara = BuildResult(score: 10, matches: ["Rule_Test"]);
        var criticalOnly = BuildResult(score: 53, matches: [], critical: true);
        var high = BuildResult(score: 82, matches: []);

        Assert.Equal("clean", CliAnalysisMapper.DetermineVerdict(low));
        Assert.Equal("suspicious", CliAnalysisMapper.DetermineVerdict(yara));
        Assert.Equal("suspicious", CliAnalysisMapper.DetermineVerdict(criticalOnly));
        Assert.Equal("likely_malicious", CliAnalysisMapper.DetermineVerdict(high));
    }

    private static PeStaticAnalyzer CreateAnalyzer()
    {
        return new PeStaticAnalyzer(new NoOpYaraScanner(), new IcedDisassembler(), new BasicCfgBuilder());
    }

    private static PeAnalysisResult BuildResult(int score, IReadOnlyList<string> matches, bool critical = false)
    {
        var findings = critical
            ? new[] { new HeuristicFinding(AnalysisSeverity.Critical, "Critico controlado", "Hallazgo critico de prueba.") }
            : [];

        return new PeAnalysisResult(
            "C:\\sample.exe",
            "sample.exe",
            10,
            new string('A', 64),
            true,
            true,
            "Amd64",
            0x1000,
            0x140000000,
            null,
            0,
            0,
            PeAdvancedMetadata.Empty,
            [new PeSectionInfo(".text", 0x1000, 10, 10, 0x400, 5.1, "0x60000020")],
            [],
            [],
            [],
            true,
            matches.Count == 0 ? "YARA ejecutado sin coincidencias." : "YARA detecto reglas.",
            matches,
            findings,
            new RiskScore(score, score >= 80 ? RiskLevel.High : RiskLevel.Low, []),
            [],
            [],
            [],
            new AnalystGuidance("Resumen", "Hipotesis", [], [], []));
    }

    private sealed class NoOpYaraScanner : IYaraScanner
    {
        public YaraScanResult Scan(string targetFilePath)
        {
            return new YaraScanResult(true, "YARA omitido en prueba controlada.", []);
        }
    }
}
