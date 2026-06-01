using Malvex.Core.Models;

namespace Malvex.Analysis;

public interface IReportExporter
{
    string ExportJson(PeAnalysisResult result, string outputDirectory);
    string ExportHtml(PeAnalysisResult result, string outputDirectory);
}
