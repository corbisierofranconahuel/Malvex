# Malvex v1.1.0

Primera release publica open source de Malvex.

## Enfoque

Malvex es una herramienta de triage estatico de archivos PE para Windows. No
intenta reemplazar IDA, Ghidra o x64dbg: prioriza una primera lectura guiada,
trazable y accesible.

## Destacados

- parser PE con secciones, entropia, imports, exports y cadenas;
- heuristicas correlacionadas y YARA local;
- Authenticode, imphash, Rich Header, callbacks TLS, recursos y PDB;
- desensamblado de entrypoint, CFG basico y vista Hex;
- navegacion desde TLS y recursos hacia Hex;
- reportes JSON y HTML;
- GUI adaptable con temas;
- portable y MSI para Windows x64;
- suite automatizada xUnit.

## Seguridad

Malvex analiza archivos localmente y no ejecuta muestras. Para analizar malware
real utiliza una maquina virtual aislada.

## Verificacion

Descarga `SHA256SUMS.txt` junto con el ZIP o MSI y compara el hash SHA256 antes
de instalar o ejecutar.
