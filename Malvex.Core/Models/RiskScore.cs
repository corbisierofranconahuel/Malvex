namespace Malvex.Core.Models;

public sealed record RiskScore(
    int Score,
    RiskLevel Level,
    IReadOnlyList<string> Reasons);
