# Publicacion sugerida para LinkedIn

## Version extensa

Hoy publico la primera version abierta de **Malvex**, una herramienta que
desarrolle para realizar triage y analisis estatico guiado de archivos PE en
Windows.

El punto de partida del proyecto fue una pregunta concreta: como hacer que una
primera lectura tecnica de un ejecutable sea mas accesible, trazable y ordenada,
especialmente para quienes todavia estan construyendo experiencia en reversing
y analisis de malware.

Malvex no busca competir con herramientas maduras como Ghidra, IDA, radare2 o
x64dbg. Ese no es su objetivo. La propuesta es diferente: reunir en una
interfaz clara las senales mas utiles para una primera etapa de investigacion y
explicar por que conviene revisar cada una.

La version `1.1.0` incluye:

- parser de archivos PE con cabeceras, secciones, imports y exports;
- calculo de entropia por seccion para detectar posibles indicadores de
  empaquetado u ofuscacion;
- extraccion priorizada de cadenas ASCII y UTF-16;
- integracion local con YARA y reglas base incluidas;
- hallazgos heuristicos correlacionados con puntaje de riesgo;
- validacion Authenticode local;
- imphash, Rich Header, callbacks TLS, recursos PE, informacion de version y
  rutas PDB;
- desensamblado localizado desde el entrypoint;
- CFG basico y vista Hex navegable por RVA;
- una capa de Analista Asistido con hipotesis, checklist dinamico y acciones
  sugeridas por prioridad;
- tutorial integrado y exportacion de reportes JSON y HTML.

Una decision de diseno importante es que Malvex mantiene el analisis estatico:
no ejecuta las muestras seleccionadas y no sube binarios, hashes ni reportes a
servicios externos. Aun asi, para investigar malware real siempre recomiendo
trabajar dentro de una maquina virtual aislada.

El proyecto es gratuito y open source bajo Apache License 2.0. Publique tanto el
codigo fuente como un instalador MSI, una version portable y hashes SHA-256 para
verificar las descargas.

Repositorio y release:
https://github.com/corbisierofranconahuel/Malvex

Esta es una primera version publica. Me interesa especialmente recibir feedback
sobre usabilidad, claridad de los mensajes guiados, falsos positivos y mejoras
que ayuden a convertir el triage inicial en un proceso mas accesible sin perder
criterio tecnico.

#Cybersecurity #MalwareAnalysis #ReverseEngineering #OpenSource #DFIR
#ThreatResearch #WindowsSecurity #YARA #DotNet

## Version breve

Publique **Malvex 1.1.0**, una herramienta open source para triage y analisis
estatico guiado de archivos PE en Windows.

El objetivo no es reemplazar Ghidra, IDA o x64dbg, sino facilitar una primera
lectura tecnica: secciones, entropia, imports/exports, strings, YARA local,
heuristicas correlacionadas, Authenticode, imphash, Rich Header, callbacks TLS,
recursos PE, desensamblado, CFG, vista Hex y una capa de Analista Asistido.

Malvex no ejecuta las muestras ni envia informacion a servicios externos.

Codigo fuente, MSI y portable:
https://github.com/corbisierofranconahuel/Malvex

#Cybersecurity #MalwareAnalysis #ReverseEngineering #OpenSource #YARA
