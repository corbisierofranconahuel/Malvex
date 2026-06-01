using Malvex.Analysis;
using Malvex.Core.Models;

namespace Malvex.App;

internal static class SectionPresentationBuilder
{
    public static IReadOnlyList<SectionDisplayRow> BuildRows(IReadOnlyList<PeSectionInfo> sections)
    {
        return sections
            .Select(section =>
            {
                var signals = SectionSignalClassifier.GetSignals(section);
                return new SectionDisplayRow(
                    section.Name,
                    section.VirtualAddress,
                    section.RawSize,
                    section.Entropy,
                    section.Characteristics,
                    signals.Count > 0 ? string.Join(" | ", signals) : "Sin señales relevantes",
                    signals.Count > 0);
            })
            .ToList();
    }

    public static string BuildSummary(IReadOnlyList<PeSectionInfo> sections)
    {
        var highlighted = sections
            .Where(section => SectionSignalClassifier.GetSignals(section).Count > 0)
            .Select(section =>
            {
                var signals = string.Join(", ", SectionSignalClassifier.GetSignals(section));
                return $"{section.Name}: {signals}";
            })
            .ToList();

        if (highlighted.Count == 0)
        {
            return "Secciones sin señales estáticas destacadas de entropía o nombre sospechoso.";
        }

        return "Secciones destacadas: " + string.Join(" | ", highlighted);
    }
}

internal sealed record SectionDisplayRow(
    string Name,
    int VirtualAddress,
    int RawSize,
    double Entropy,
    string Characteristics,
    string Signal,
    bool HasSignal);
