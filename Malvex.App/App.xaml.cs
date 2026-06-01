using System.Configuration;
using System.Data;
using System.Windows;
using System.Windows.Threading;

namespace Malvex.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        StartupDiagnostics.Log("App startup begin.");
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnCurrentDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

        try
        {
            var window = new MainWindow();
            window.Loaded += (_, _) => StartupDiagnostics.Log("MainWindow loaded.");
            window.ContentRendered += (_, _) => StartupDiagnostics.Log("MainWindow content rendered.");
            MainWindow = window;
            window.Show();
            StartupDiagnostics.Log("MainWindow shown.");
        }
        catch (Exception ex)
        {
            StartupDiagnostics.Log($"Fatal startup error: {ex}");
            MessageBox.Show(
                $"Malvex no pudo iniciar.\n\nDetalle:\n{ex.Message}\n\nRevisa el log en %LOCALAPPDATA%\\Malvex\\logs\\startup.log",
                "Malvex",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(-1);
        }
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        StartupDiagnostics.Log($"DispatcherUnhandledException: {e.Exception}");
        e.Handled = true;
        MessageBox.Show(
            "Malvex encontro un error inesperado en la interfaz, pero evito el cierre de la aplicacion.\n\n" +
            $"Detalle: {e.Exception.Message}\n\n" +
            "Recomendacion: guarda el reporte si es posible, reinicia la aplicacion y revisa el log en " +
            "%LOCALAPPDATA%\\Malvex\\logs\\startup.log",
            "Malvex",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }

    private static void OnCurrentDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        StartupDiagnostics.Log($"AppDomainUnhandledException: {e.ExceptionObject}");
    }

    private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        StartupDiagnostics.Log($"UnobservedTaskException: {e.Exception}");
    }
}
