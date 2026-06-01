namespace Malvex.Analysis;

public interface IYaraScanner
{
    YaraScanResult Scan(string targetFilePath);
}
