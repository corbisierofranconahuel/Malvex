namespace Malvex.Core.Models;

public sealed record AuthenticodeInfo(
    AuthenticodeStatus Status,
    string Description,
    string? Subject,
    string? Issuer);
