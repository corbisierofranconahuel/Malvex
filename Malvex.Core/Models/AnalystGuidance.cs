namespace Malvex.Core.Models;

public sealed record AnalystGuidance(
    string BeginnerSummary,
    string ExpertSummary,
    IReadOnlyList<AnalysisHypothesis> Hypotheses,
    IReadOnlyList<AnalystChecklistItem> Checklist,
    IReadOnlyList<SuggestedAction> SuggestedActions);
