using Malvex.Analysis;
using Malvex.Core.Models;

namespace Malvex.App;

internal sealed class AnalysisSessionService
{
    private readonly IPeStaticAnalyzer _analyzer;
    private readonly IReportExporter _reportExporter;

    public AnalysisSessionService(IPeStaticAnalyzer analyzer, IReportExporter reportExporter)
    {
        _analyzer = analyzer;
        _reportExporter = reportExporter;
    }

    public PeAnalysisResult Analyze(string filePath)
    {
        return _analyzer.Analyze(filePath);
    }

    public string ExportJson(PeAnalysisResult result)
    {
        return _reportExporter.ExportJson(result, AppPaths.ReportsDirectory);
    }

    public string ExportHtml(PeAnalysisResult result)
    {
        return _reportExporter.ExportHtml(result, AppPaths.ReportsDirectory);
    }
}
