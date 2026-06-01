# Tutorial de Malvex

Creado por Franco Nahuel Corbisiero

## Flujo recomendado
1. `Resumen`: abrir y analizar un `.exe/.dll`.
2. `Analista Asistido`: revisar hipótesis y acciones sugeridas.
3. `Desensamblado` + `CFG`: validar lógica y flujo.
4. `Vista Hex`: inspección de bytes por RVA.
5. Exportar JSON/HTML.

## Tips rápidos
- Usa la búsqueda de cadenas para localizar URLs, comandos o rutas relevantes.
- Si el puntaje es alto, prioriza acciones `P1` en Analista Asistido.
- Para reproducibilidad, guarda siempre reportes y hash.
- Malvex no ejecuta muestras: cualquier validación dinámica debe realizarse externamente en una sandbox aislada.
