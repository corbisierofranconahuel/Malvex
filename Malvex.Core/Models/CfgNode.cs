namespace Malvex.Core.Models;

public sealed record CfgNode(
    int Id,
    int StartRva,
    int EndRva,
    IReadOnlyList<int> SuccessorIds);
