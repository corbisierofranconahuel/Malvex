using Malvex.Core.Models;

namespace Malvex.Analysis;

public interface IPeStaticAnalyzer
{
    PeAnalysisResult Analyze(string filePath, int maxStrings = 300);
}
