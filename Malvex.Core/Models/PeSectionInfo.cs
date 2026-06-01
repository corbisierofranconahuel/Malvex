namespace Malvex.Core.Models;

public sealed record PeSectionInfo(
    string Name,
    int VirtualAddress,
    int VirtualSize,
    int RawSize,
    int RawPointer,
    double Entropy,
    string Characteristics);
