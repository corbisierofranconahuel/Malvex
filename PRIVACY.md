# Politica de privacidad

Malvex esta disenado para analizar archivos PE de Windows localmente.

## Tratamiento de datos

- Los binarios seleccionados se leen localmente para analizarlos.
- Malvex no sube muestras, hashes ni reportes a servicios externos.
- Malvex no requiere conexion a Internet para analizar archivos.
- Los reportes JSON y HTML exportados se guardan localmente en
  `%LOCALAPPDATA%\Malvex\reports`.
- Las preferencias visuales y diagnosticos de inicio se guardan localmente en
  `%LOCALAPPDATA%\Malvex`.

## Herramientas externas

YARA se ejecuta localmente desde `tools/yara/` o desde el `PATH` del sistema. Si
una version futura agrega servicios opcionales de reputacion, deberan activarse
explicitamente y documentarse antes de realizar cualquier solicitud de red.

## Responsabilidad

Revisa los reportes exportados antes de compartirlos: pueden contener hashes,
nombres de archivo, cadenas, rutas PDB y otros metadatos extraidos del archivo.
