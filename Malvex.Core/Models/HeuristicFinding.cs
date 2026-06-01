namespace Malvex.Core.Models;

public sealed record HeuristicFinding(
    AnalysisSeverity Severity,
    string Title,
    string Description);
