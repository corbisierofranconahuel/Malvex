namespace Malvex.Core.Models;

public sealed record GuidedStep(
    int Order,
    string Title,
    string Description);
