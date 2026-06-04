namespace Malvex.Cli;

public sealed record CliOptions(
    string Command,
    string FilePath,
    string Format,
    bool PrettyJson,
    int MaxStrings,
    long MaxSizeBytes)
{
    public static bool TryParse(string[] args, out CliOptions options, out string error)
    {
        options = new CliOptions("analyze", string.Empty, "json", false, 800, 512L * 1024 * 1024);
        error = string.Empty;

        if (args.Length == 0 || args.Any(a => a is "-h" or "--help" or "help"))
        {
            error = Usage;
            return false;
        }

        var command = args[0].Equals("analyze", StringComparison.OrdinalIgnoreCase)
            ? "analyze"
            : string.Empty;
        if (string.IsNullOrWhiteSpace(command))
        {
            error = "Comando invalido.\n\n" + Usage;
            return false;
        }

        if (args.Length < 2)
        {
            error = "Falta la ruta del archivo a analizar.\n\n" + Usage;
            return false;
        }

        var filePath = args[1];
        var format = "json";
        var pretty = false;
        var maxStrings = 800;
        var maxSizeMb = 512;

        for (var i = 2; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case "--json":
                    format = "json";
                    break;
                case "--wazuh":
                    format = "wazuh";
                    break;
                case "--pretty":
                    pretty = true;
                    break;
                case "--max-strings":
                    if (!TryReadInt(args, ref i, out maxStrings) || maxStrings < 0)
                    {
                        error = "--max-strings requiere un entero >= 0.";
                        return false;
                    }
                    break;
                case "--max-size-mb":
                    if (!TryReadInt(args, ref i, out maxSizeMb) || maxSizeMb <= 0)
                    {
                        error = "--max-size-mb requiere un entero > 0.";
                        return false;
                    }
                    break;
                default:
                    error = $"Argumento desconocido: {arg}\n\n{Usage}";
                    return false;
            }
        }

        options = new CliOptions(command, filePath, format, pretty, maxStrings, maxSizeMb * 1024L * 1024L);
        return true;
    }

    public const string Usage =
        """
        Uso:
          Malvex.Cli.exe analyze <archivo.exe|archivo.dll> [--json|--wazuh] [--pretty] [--max-size-mb N] [--max-strings N]

        Salidas:
          --json     JSON estructurado para SIEM o automatizacion (por defecto).
          --wazuh    Linea compacta key=value para reglas simples de Wazuh.

        Exit codes:
          0  Analizado sin alerta operativa.
          1  Sospechoso o probablemente malicioso.
          2  Error tecnico.
          3  Archivo no PE.
          64 Argumentos invalidos.
        """;

    private static bool TryReadInt(string[] args, ref int index, out int value)
    {
        value = 0;
        if (index + 1 >= args.Length)
        {
            return false;
        }

        index++;
        return int.TryParse(args[index], out value);
    }
}
