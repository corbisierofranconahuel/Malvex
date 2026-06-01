namespace Malvex.Core.Models;

public sealed record SuggestedAction(
    int Priority,
    string Action,
    string Reason);
