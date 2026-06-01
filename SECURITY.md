# Politica de seguridad

## Versiones soportadas

Las correcciones de seguridad se aplican a la ultima version publicada de Malvex.

## Reportar una vulnerabilidad

No publiques detalles sensibles de vulnerabilidades en un issue publico.

Usa el reporte privado de vulnerabilidades de GitHub o abre un issue sin datos
sensibles solicitando un canal privado si esa funcion aun no esta activada.

Incluye:

- version afectada;
- pasos para reproducir el problema;
- comportamiento esperado y observado;
- impacto de seguridad;
- logs o capturas sin datos sensibles.

## Seguridad al manipular muestras

Malvex realiza analisis estatico y no ejecuta las muestras seleccionadas. Trata
las muestras como peligrosas de todos modos: usa una maquina virtual aislada,
desactiva carpetas compartidas cuando corresponda y nunca subas binarios
confidenciales a servicios externos sin autorizacion.
