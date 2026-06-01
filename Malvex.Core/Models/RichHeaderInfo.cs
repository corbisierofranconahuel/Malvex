namespace Malvex.Core.Models;

public sealed record RichHeaderInfo(
    bool IsPresent,
    string Hash,
    int EntryCount,
    uint XorKey)
{
    public static RichHeaderInfo Empty { get; } = new(false, string.Empty, 0, 0);
}
