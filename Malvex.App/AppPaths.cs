using System.IO;

namespace Malvex.App;

internal static class AppPaths
{
    private static readonly string Root = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Malvex");

    public static string PreferencesFile => EnsureDirectory(Path.Combine(Root, "ui-preferences.json"));
    public static string StartupLogFile => EnsureDirectory(Path.Combine(Root, "logs", "startup.log"));
    public static string ReportsDirectory => EnsureDirectory(Path.Combine(Root, "reports"));

    private static string EnsureDirectory(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        return path;
    }

    public static string EnsureDirectoryPath(string directoryPath)
    {
        Directory.CreateDirectory(directoryPath);
        return directoryPath;
    }
}
