namespace Malvex.Core.Models;

public sealed record AnalystChecklistItem(
    string Item,
    bool AutoVerified,
    string Notes);
