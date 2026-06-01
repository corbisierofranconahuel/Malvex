namespace Malvex.Analysis;

public sealed record YaraScanResult(
    bool IsAvailable,
    string Message,
    IReadOnlyList<string> Matches);
