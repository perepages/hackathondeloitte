# Estado actual del proyecto · Triaje N1 Tarvia (reto Deloitte × UAB The Hack)

7 nov 2026 · rama `perebranch` (último commit `5e6848e` + cambios sin commit del veredicto real) · 43 tests en verde

## 1. En una frase

Tenemos una app Streamlit que revisa alertas de seguridad del SOC de Tarvia (comprueba los datos con la API
de Deloitte, propone una conclusión y lo explica en lenguaje claro) y deja la decisión a una persona. Funciona
con la muestra de 150 alertas y en vivo con la API real. **El veredicto, la propuesta y las acciones ya los da el
back** (LLM + reglas de respaldo + política SOC encima, en `verdict.py`); solo `incident_id` sigue siendo de ejemplo.

## 2. Qué funciona hoy

| Pieza | Estado |
| --- | --- |
| Recogida de evidencias por alerta (back, `triage.py`) | ✅ Inventario, empleados, inteligencia, sandbox, cambios aprobados y registros de ±24 h. ~2 s por alerta |
| Gravedad con la matriz de la política (back, `policy.py`) | ✅ Con ajuste por identidad VIP o privilegiada |
| Veredicto, propuesta (cerrar/escalar) y acciones | ✅ `verdict.decide` (back): propuesta del LLM en JSON (`assistant.decide_json`, ~10 s); si falla o no hay clave, las reglas de `scripts/nivel1_triage.py`. La política se aplica siempre encima (gravedad, escalado obligatorio, aprobaciones, OT, uso dual). `decision_source` dice de dónde salió |
| Detección de intentos de engaño (texto oculto para el clasificador) | ✅ En el back, siempre: fuerza `true_positive` + escalar y la gravedad no puede bajar |
| Gravedad según la conclusión | ✅ Actividad autorizada o falsa alarma → informational/low; ajustes ±1 como máximo en total; ataque real informativo (bloqueado sin efecto) se cierra |
| Plan de acción con IA (`assistant.py`) | ✅ Pasarela LLM de la UAB (modelo `ornith`), ~6 s. Rechaza instrucciones ocultas en los datos. Ollama soportado pero sin probar (no está instalado) |
| Front: 7 páginas | ✅ Inicio, Alertas, Informe para N2, Acciones de respuesta, Triaje en directo, Resumen, Incidentes (+ «Prototipo del back») |
| Modo en vivo (`SOC_MODE=live`) | ✅ Probado con 10 alertas reales fuera de la muestra: ~16 s, 8 cerradas y 2 escaladas |
| Decisión de la persona | ✅ Guardada en SQLite (`data/soc.db`): quién, cuándo, si corrigió al sistema, nota |
| Informe en formato Deloitte | ✅ Los 150 informes cumplen `ticket_salida.schema.json` |
| Contención con aprobación (nivel 4) | ✅ Pendiente → aprobada (N2) → hecha; reglas de la política (sin aprobación: bloquear IOC y borrar correo; nada sobre OT). Simulada en modo muestra |
| Incidentes (niveles 2-3) | ⚠️ Pantalla hecha, pero el back no genera `incident_id`: solo hay un incidente de ejemplo |

## 3. Decisiones técnicas clave

1. **Todo en Python y Streamlit, sin API intermedia.** El front importa directamente el back (`triage.py`,
   `assistant.py`). La única API es la simulada de Deloitte (puerto 8000).
2. **Una sola puerta a los datos: `core/data.py`.** Traduce la salida del back (`TriagePreview`, en `schemas.py`)
   al formato que leen las pantallas (`to_view()`). Si el back cambia, solo se toca este fichero. El contrato
   completo está documentado al principio de `core/data.py`.
3. **Dos modos.**
   - `SOC_MODE=fixture` (por defecto): lee `data/fixture.json` (150 alertas con la salida real del back), sin red.
   - `SOC_MODE=live`: llama al back contra la API de Deloitte.
4. **Campos de ejemplo transparentes.** Lo que el back aún no da sale de reglas de prueba, se lista en
   `example_fields` y se marca en pantalla. Cuando el back lo dé, manda el suyo sin tocar las pantallas.
   `SOC_EXAMPLES=0` los quita.
5. **Seguridad ante el atacante.** El texto de las alertas nunca se pinta como HTML (`ui.md`, `ui.esc`), y al LLM se
   le pasa dentro de `<datos_no_fiables>` con la orden de no obedecerlo. Probado con el correo
   `ALR-20261020-011905`, que intenta forzar un «falso positivo».
6. **El LLM solo redacta.** No cambia veredicto ni gravedad ni ejecuta nada. Va con el razonamiento desactivado
   (`chat_template_kwargs.enable_thinking=false`): con él, `ornith` gastaba los tokens pensando y no respondía.
7. **La persona decide y queda registrado.** Ninguna acción se ejecuta sin aprobación, salvo las que la política
   permite al N1.
8. **Diseño para alguien de fuera del SOC.** Lenguaje claro («Ataque real», «Falsa alarma»…), cada consulta a la
   API traducida a una frase, y línea visual de Deloitte: negro y blanco, azul `#1076A8` para lo interactivo,
   verde `#86BC25` solo de acento, Open Sans. El logo de Deloitte sale de la presentación oficial del reto.
   Los colores de datos (conclusión y gravedad) están validados para daltonismo.
9. **La clave del LLM no se sube nunca:** va en `.env` (ignorado por git); `.env.example` explica qué poner.

## 4. Cómo funciona el código

```
app.py ── navegación (st.navigation), tema, logo
  └─ views/                 una página por fichero
       inicio.py            qué es el sistema, flujo en 4 pasos, cifras, recorrido de la demo
       cola.py              Alertas: bandeja arriba + ficha de la alerta elegida debajo (5 pasos, IA, decisión)
       ticket.py            Informe para N2 en formato Deloitte, validado y descargable
       contencion.py        Acciones de respuesta: tarjetas por alerta + aprobar/ejecutar + registro
       directo.py           Triaje en directo: kanban Entran → Investigando → Cerradas / Esperan a una persona
       panel.py             Resumen: cifras, conclusiones, mapa de gravedad, por día, SLA
       incidentes.py        Alertas agrupadas por incident_id + línea temporal MITRE
       mvp_back.py          primera app del back, conservada
  └─ core/
       data.py              ÚNICA puerta a los datos: to_view, load_results, run_triage, analyze_live,
                            suggest_ids, approve/contain, llm_status/action_plan
       store.py             SQLite con las decisiones de la persona
       ui.py                colores, etiquetas en lenguaje claro, badges, matriz, tarjetas, barra de pasos
back (raíz)
  soc_api.py               cliente HTTP de la API de Deloitte
  triage.py                analyze_alert(id) -> TriagePreview (evidencias + gravedad + preguntas abiertas)
  policy.py · schemas.py   matriz de gravedad · modelos Pydantic
  assistant.py             plan de acción con LLM (pasarela UAB u Ollama)
scripts/
  build_fixture.py         regenera data/fixture.json (necesita la API)
  nivel1_triage.py         reglas de ejemplo (veredicto, decisión) mientras el back no lo da
```

**Recorrido de una alerta:** `data.run_triage` / `data.analyze_live` → `triage.analyze_alert` consulta la API →
`to_view` añade la frase de cada consulta y, si faltan, los campos de ejemplo → la pantalla lo pinta → la persona
decide (`store.save_review`) → el informe se construye con `ticket.build_ticket` y se valida contra el esquema.

**Arrancar:**
```powershell
python -m venv .venv; .venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env      # y poner LLM_API_KEY (web de recursos de la hackatón)
.venv\Scripts\python.exe -m streamlit run app.py                         # con la muestra, sin red
$env:SOC_MODE="live"; .venv\Scripts\python.exe -m streamlit run app.py   # con la API de Deloitte en :8000
.venv\Scripts\python.exe -m pytest -q                                    # 34 tests
```
La API de Deloitte se arranca desde `../DTT-UAB-The-Hack/06_herramientas` con
`python -m uvicorn mock_soc_api:app --port 8000`.

## 5. Ramas

- `perebranch`: la buena, con todo integrado (A + B + back) y subida a GitHub.
- `front-a` y `front-b`: se han quedado atrás. Quien vuelva a trabajar en ellas tiene que hacer `git merge perebranch` antes.
- `main`: solo el back original (primera versión + «Integració LLM»). No se ha tocado.

## 6. Pendiente y cosas a vigilar

- **Hablar con el equipo del back** del veredicto con LLM (`verdict.py`): ellos eligieron Ollama, que está soportado
  (`assistant._complete_ollama`, con `format="json"`) pero sin probar.
- Modo en vivo más lento: ~10 s más por alerta por la llamada al LLM. `SOC_VERDICT_ENGINE=rules` lo evita (solo reglas).
- Discrepancias discutibles con las reglas (en `data/comparacion_veredictos.json`): el LLM escala phishing confirmado
  de gravedad baja (las reglas lo cierran tras purgar y bloquear); da por autorizados un bucket público hecho desde CI
  (UC-CLD-003) y una subida a WeTransfer (UC-DLP-001); llama falsa alarma a escáneres bloqueados por el WAF.
- `incident_id` lo debería generar el back (agrupar por equipo/usuario/indicador compartido en una ventana de tiempo).
- `on_event` en `analyze_alert` para que el directo muestre las consultas en tiempo real (hoy salen al acabar cada alerta).
- Guion de la demo («camino feliz») y ensayo: lo haremos aparte.
- La guía visual publicada (https://claude.ai/artifact/9TxhFkL7oNJ9bhKroUUrjs) tiene capturas del diseño anterior.
- `docs/PLAN_FRONTEND.md` describe el plan inicial; el contrato vigente está en `core/data.py`.
- Si se cambia `core/ui.py` con la app abierta, hay que reiniciar Streamlit.

## 7. Paso exacto siguiente

**Hecho (7 nov, noche): back de Marc integrado y gravedad corregida.**
- `rules.py`: motor de reglas = runbooks RB-01…RB-10 de Marc (rama `pozobranch`), en castellano y con sus errores
  corregidos (TIP «known-good» tomado como malicioso, cambios aprobados sin mirar fecha, pentest por fecha y no por
  IP, simulacro/SCCM con una palabra suelta, viaje de RRHH sin fechas, ATO por subcadena, frases cortas al asistente)
  + nuestras reglas por caso de uso + regla nueva RB-03 de VPN de proveedor. Es el respaldo si falla la IA y, si no,
  una **segunda opinión** visible en la ficha (`second_opinion`).
- Gravedad (§2): se busca siempre el activo afectado (puesto del usuario, frontal de la tienda, asistente Vela,
  bucket); antes solo 51/150 alertas tenían activo, ahora 145/150. La matriz está comprobada celda a celda contra
  `politica_soc.md` (test). El calendario de cambios está en **hora de España** (UTC+2/UTC+1) y se convierte a UTC.
- Política encima de la IA: −1 si un control lo bloqueó; +1 si un runbook confirma acceso o ejecución; gravedad
  baja o informativa no se escala salvo criterio obligatorio §5; a la IA solo se le marcan como autorizados los
  cambios que cubren de verdad la alerta.
- Resultado con las 150 alertas: IA y reglas coinciden en 136/150 veredictos; 22 escaladas, todas graves o
  obligatorias; 0 incoherencias (escalada informativa o ataque grave cerrado). 64 tests en verde.
- No se ha juntado la rama `pozobranch` con git: su `app.py` es la app antigua y sus campos no encajaban con el front.

**Siguiente: agrupar alertas en incidentes (`incident_id`, política §6).** Ejemplo claro en la muestra: los tres
accesos VPN de Logisoft (11, 18 y 25 de octubre, domingos de madrugada desde el mismo ASN) son un mismo incidente.
