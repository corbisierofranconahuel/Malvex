using Malvex.Analysis;

namespace Malvex.Tests;

public sealed class AdvancedAnalysisTests
{
    [Fact]
    public void AnalyzeAssembly_ReturnsStableAdvancedMetadata()
    {
        var target = typeof(PeStaticAnalyzer).Assembly.Location;

        var result = CreateAnalyzer().Analyze(target);

        Assert.True(result.IsPe);
        Assert.NotEmpty(result.Sections);
        Assert.Equal(64, result.Sha256.Length);
        Assert.NotNull(result.AdvancedMetadata);
        Assert.NotNull(result.AdvancedMetadata.Authenticode);
    }

    [Fact]
    public void AnalyzeMalformedFile_ReturnsGuidedNonPeResult()
    {
        var path = Path.Combine(Path.GetTempPath(), $"malvex-invalid-{Guid.NewGuid():N}.bin");
        try
        {
            File.WriteAllBytes(path, [0x4D, 0x5A, 0x00, 0x01, 0x02, 0x03]);

            var result = CreateAnalyzer().Analyze(path);

            Assert.False(result.IsPe);
            Assert.Contains(result.Findings, finding => finding.Title == "Archivo no PE");
            Assert.Contains("PE", result.GuidedSteps[0].Description, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void DisassembleCodeWindow_PreservesRvaAndOriginalFileOffset()
    {
        var instructions = new IcedDisassembler()
            .DisassembleCodeWindow([0x90, 0xC3], 0x1234, true, 0x140000000, 0x400);

        Assert.Equal(2, instructions.Count);
        Assert.Equal("nop", instructions[0].Mnemonic);
        Assert.Equal(0x1234, instructions[0].Rva);
        Assert.Equal(0x400, instructions[0].FileOffset);
        Assert.Equal("ret", instructions[1].Mnemonic);
        Assert.Equal(0x401, instructions[1].FileOffset);
    }

    [Fact]
    public void GitExecutable_WhenInstalled_ExposesTlsAndValidAuthenticode()
    {
        if (!OperatingSystem.IsWindows()
            || Environment.GetEnvironmentVariable("MALVEX_RUN_WINDOWS_INTEGRATION_TESTS") != "1")
        {
            return;
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var gitPath = Path.Combine(programFiles, "Git", "cmd", "git.exe");
        if (!File.Exists(gitPath))
        {
            return;
        }

        var result = CreateAnalyzer().Analyze(gitPath);

        Assert.True(result.IsPe);
        Assert.NotEmpty(result.AdvancedMetadata.TlsCallbackVas);
        Assert.Equal(Malvex.Core.Models.AuthenticodeStatus.Valid, result.AdvancedMetadata.Authenticode.Status);
        Assert.NotEmpty(result.AdvancedMetadata.Resources);
    }

    private static PeStaticAnalyzer CreateAnalyzer()
    {
        return new PeStaticAnalyzer(new NoOpYaraScanner(), new IcedDisassembler(), new BasicCfgBuilder());
    }

    private sealed class NoOpYaraScanner : IYaraScanner
    {
        public YaraScanResult Scan(string targetFilePath)
        {
            return new YaraScanResult(true, "YARA omitido en prueba controlada.", []);
        }
    }
}
