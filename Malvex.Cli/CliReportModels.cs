namespace Malvex.Cli;

public sealed record CliAnalysisReport(
    string Tool,
    string Version,
    string Verdict,
    double Confidence,
    int RiskScore,
    string RiskLevel,
    string HighestSeverity,
    bool IsPe,
    CliFileSummary File,
    CliYaraSummary Yara,
    CliAnalysisCounts Counts,
    IReadOnlyList<CliFinding> Findings,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<CliSectionSummary> Sections,
    IReadOnlyList<string> Guidance);

public sealed record CliFileSummary(
    string Path,
    string Name,
    long SizeBytes,
    string Sha256,
    string Architecture,
    string Bitness,
    string EntryPointRva,
    string ImageBase,
    DateTimeOffset? CoffTimestampUtc);

public sealed record CliYaraSummary(
    bool Available,
    string Message,
    IReadOnlyList<string> Matches);

public sealed record CliAnalysisCounts(
    int Sections,
    int ImportLibraries,
    int ImportedFunctions,
    int Exports,
    int Strings,
    int Findings,
    int Instructions,
    int CfgNodes);

public sealed record CliFinding(
    string Severity,
    string Title,
    string Description);

public sealed record CliSectionSummary(
    string Name,
    string VirtualAddress,
    int RawSize,
    double Entropy,
    string Characteristics);
