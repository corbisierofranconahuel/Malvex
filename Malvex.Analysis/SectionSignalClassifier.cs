using Malvex.Core.Models;

namespace Malvex.Analysis;

public static class SectionSignalClassifier
{
    public const double HighEntropyThreshold = 7.2;

    public static bool HasHighEntropy(PeSectionInfo section)
    {
        return section.RawSize > 0 && section.Entropy >= HighEntropyThreshold;
    }

    public static bool HasSuspiciousName(PeSectionInfo section)
    {
        return StaticAnalysisPatterns.SuspiciousSectionNames.Any(name =>
            section.Name.Contains(name, StringComparison.OrdinalIgnoreCase));
    }

    public static IReadOnlyList<string> GetSignals(PeSectionInfo section)
    {
        var signals = new List<string>();

        if (HasHighEntropy(section))
        {
            signals.Add($"Entropia alta ({section.Entropy:0.000})");
        }

        if (HasSuspiciousName(section))
        {
            signals.Add("Nombre asociado a packer");
        }

        if (section.RawSize == 0)
        {
            signals.Add("RawSize = 0");
        }

        return signals;
    }

    public static string DescribeSection(PeSectionInfo section)
    {
        var parts = new List<string> { section.Name };

        if (HasHighEntropy(section))
        {
            parts.Add($"H={section.Entropy:0.000}");
        }

        if (HasSuspiciousName(section))
        {
            parts.Add("packer-name");
        }

        return string.Join(" | ", parts);
    }
}
