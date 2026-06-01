namespace Malvex.Core.Models;

public sealed record AnalysisHypothesis(
    string Title,
    HypothesisConfidence Confidence,
    IReadOnlyList<string> Evidence);
