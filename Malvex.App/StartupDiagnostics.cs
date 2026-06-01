using System.Text;
using System.IO;

namespace Malvex.App;

internal static class StartupDiagnostics
{
    private static readonly object Gate = new();
    private static readonly string LogPath = AppPaths.StartupLogFile;

    public static void Log(string message)
    {
        try
        {
            lock (Gate)
            {
                var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}";
                File.AppendAllText(LogPath, line, Encoding.UTF8);
            }
        }
        catch
        {
            // Never break app startup because of logging.
        }
    }
}
