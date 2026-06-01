namespace Malvex.Core.Models;

public sealed record ImportLibrary(
    string Name,
    IReadOnlyList<string> Functions);
