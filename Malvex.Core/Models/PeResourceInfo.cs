namespace Malvex.Core.Models;

public sealed record PeResourceInfo(
    string Type,
    string Name,
    string Language,
    int DataRva,
    int Size);
