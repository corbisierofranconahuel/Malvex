# Historial de cambios

Los cambios relevantes de Malvex se documentan aqui.

## [Unreleased]

### Agregado

- Proyecto `Malvex.Cli` para automatizacion, SIEM y pipelines defensivos.
- Salida JSON estable con `verdict`, `confidence`, `risk_score`, YARA,
  hallazgos, secciones destacadas y acciones sugeridas.
- Salida compacta `--wazuh` para integracion inicial con Wazuh o reglas simples.
- Codigos de salida para automatizacion: OK, alerta, error tecnico, no PE y
  argumentos invalidos.
- Guia `docs/WAZUH_INTEGRATION.md`.
- Paquetes portable/MSI preparados para incluir `Malvex.Cli.exe`.

## [1.1.0] - 2026-06-01

### Agregado

- Triage estatico PE guiado con puntaje de riesgo, heuristicas y correlacion YARA.
- Secciones PE, entropia, imports, exports y cadenas priorizadas.
- Desensamblado del entrypoint, CFG basico y vista Hex basada en RVA.
- Validacion Authenticode mediante APIs locales de confianza de Windows.
- Imphash, fingerprint Rich Header, ruta PDB y metadatos de version.
- Deteccion de callbacks TLS con navegacion directa a Hex y desensamblado localizado.
- Inventario seguro de recursos PE con navegacion directa a Hex.
- Reportes JSON y HTML.
- Interfaz WPF adaptable con multiples temas.
- Suite de regresion xUnit.

### Modificado

- Los hallazgos informativos ya no aumentan el puntaje de riesgo por si solos.
- El contenido largo queda limitado dentro de su panel para preservar la adaptabilidad.

### Seguridad

- Malvex sigue siendo exclusivamente estatico: no ejecuta muestras seleccionadas.
