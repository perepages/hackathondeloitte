# Plan de frontend en Streamlit · Triaje N1 Tarvia

7 nov 2026 · Pere · Copia del documento vivo: https://claude.ai/artifact/1qah4Mo2UYyjNkucHodzVA
(si este fichero y el documento no coinciden, manda el documento).

## Persona B: empieza aquí

Eres **B, «la operación»**. Tu rama es `front-b`. Tus ficheros:

| Fichero | Qué hacer primero |
| --- | --- |
| `views/directo.py` | Diseño del kanban y de las tarjetas; botón «Abrir en la cola» al acabar |
| `views/panel.py` | Mapa de calor de severidades, alertas por día y SLA |
| `views/incidentes.py` | Tarjeta de incidente y línea temporal (solo si hay tiempo) |
| `core/data.py`, `core/store.py` | Ya funcionan. Son la puerta a los datos: cualquier cambio del back se adapta aquí |
| `data/fixture.json`, `scripts/build_fixture.py` | Datos de ejemplo; se regeneran con la API arrancada |

1. `git checkout front-b`, crear el entorno y arrancar (ver **Paso 0**).
2. Lee **Contrato de datos** y **Persona B** de este documento.
3. Cada fichero empieza con un comentario con sus `TODO B`.
4. Antes de cada merge a `perebranch`: `.venv\Scripts\python.exe -m pytest -q` en verde.

## Objetivo

Construimos en Streamlit la demo visual obligatoria del triaje N1. La hacen dos personas en paralelo:
**A, «el analista»**, que muestra una alerta en profundidad, y **B, «la operación»**, que muestra todas las
alertas, el directo y el negocio. Las dos partes se apoyan en el mismo contrato de datos, así el back se enchufa
sin tocar las páginas.

Deloitte pide **ver** cómo la IA hace el triaje:

- la cola de alertas;
- qué consulta el sistema;
- en qué se basa para decidir;
- qué propone;
- dónde interviene la persona.

Valoran que el triaje sea correcto y esté bien argumentado, que funcione sobre los datos reales, que esté claro
qué decide la IA y qué la persona, y que seamos honestos con lo que no resolvemos. El último día nos darán unas
alertas sorpresa para triar en directo.

La presentación cuenta una sola historia, y cada paso es de una persona:

1. Llegan 10 alertas y el sistema las tría en directo (B, página En directo).
2. Abrimos una y vemos cómo la ha investigado (A, página Cola).
3. Las que se escalan esperan a la persona, que acepta o corrige (A).
4. El N2 recibe un ticket listo para actuar (A, página Ticket).
5. Cerramos con el valor para el negocio (B, página Panel).

Referencia visual: la maqueta HTML (`demo/triaje_demo.html`, también en
https://claude.ai/artifact/LKsJG1zg454mDhKRjJt2qf) ya tiene la cola, el directo y el panel funcionando.
Copiad de ahí qué se muestra y los colores; el código es nuevo, en Streamlit.

## Arquitectura y ficheros

Streamlit es Python, así que importa directamente el motor de triaje del back (`triage.py`) y no hace falta una
API intermedia. Las páginas nunca leen ficheros ni llaman a la API de Deloitte: todo pasa por `core/data.py`.

```
app.py · navegación                                   (A)
  ├── Páginas de A: views/cola.py · ticket.py · contencion.py
  └── Páginas de B: views/directo.py · panel.py · incidentes.py
          │  (las páginas solo llaman a core/)
          ▼
core/ui.py (A)        core/data.py (B)              core/store.py (B)
colores, etiquetas,   única puerta a los datos      decisiones del analista
matriz                  │                 │                 │
                        ▼                 ▼                 ▼
            data/fixture.json      triage.py (back)     data/soc.db
            SOC_MODE=fixture       SOC_MODE=live        SQLite
                                         │
                                         ▼
                                 API Deloitte :8000 (mock_soc_api)
```

| Fichero | Dueño | Qué hace |
| --- | --- | --- |
| `app.py` | A | Punto de entrada: `st.set_page_config`, `st.navigation` con las páginas, CSS común |
| `core/ui.py` | A | Colores, etiquetas de severidad y veredicto, matriz de severidad, lista de consultas. Lo usan las dos personas |
| `core/data.py` | B | Única puerta a los datos: cargar resultados, triar en directo, aprobar y contener |
| `core/store.py` | B | SQLite (`data/soc.db`): decisiones del analista |
| `data/fixture.json` | B (A puede añadir) | 150 alertas: salida real del back + campos de ejemplo |
| `views/cola.py` | A | Cola + detalle de una alerta en 5 pasos + decisión de la persona |
| `views/ticket.py` | A | Ficha de ticket en el formato de Deloitte, descargable |
| `views/contencion.py` | A | Nivel 4: proponer, aprobar y ejecutar contención |
| `views/directo.py` | B | Cargar alertas sorpresa y triarlas en vivo (kanban) |
| `views/panel.py` | B | Panel de negocio + SLA |
| `views/incidentes.py` | B | Niveles 2-3: alertas agrupadas y línea temporal |
| `views/mvp_back.py` | back | Primera app del back, conservada como referencia |

La carpeta se llama `views/` y no `pages/` a propósito: con `st.navigation`, una carpeta `pages/` activaría el
menú automático de Streamlit y saldrían páginas duplicadas.

## Contrato de datos

El back entrega un `TriagePreview` por alerta (Pydantic, en `schemas.py`). `core/data.py` lo traduce con
`to_view()` a un diccionario plano, que es el contrato del front. Las páginas solo leen ese diccionario; la lista
completa de campos está al principio de `core/data.py`.

| Campos | Qué son | Vienen de |
| --- | --- | --- |
| `alert_id`, `alert`, `created_at`, `rule_id`, `rule_name`, `source_product`, `rule_severity` | La alerta original de Deloitte | back |
| `severity`, `severity_rationale` | Severidad con la matriz §2, calculada por el back | back |
| `asset_criticality` | Criticidad del activo más crítico | back (`contexts`) |
| `queries` | Consultas a la API con `status` (`ok`, `not_found`, `error`) y una frase legible en `summary` | back + frase del front |
| `contexts`, `related_logs` | CMDB, usuarios, inteligencia y logs de ±24 h | back |
| `open_questions` | Lo que no se pudo resolver | back |
| `verdict`, `confidence`, `justification` | Veredicto | ejemplo (el back siempre da `needs_more_info`) |
| `decision` | `close` o `escalate` | ejemplo |
| `title`, `summary`, `recommended_actions`, `injection_flags`, `incident_id` | Ticket, acciones, inyección y agrupación | ejemplo |
| `example_fields` | Qué campos vienen de ejemplo | front |
| `review` | Decisión de la persona: `{decision, analyst, note, at}` | `core/store.py` |

Tres reglas del contrato:

- **Un campo de ejemplo se marca en pantalla** con `ui.example_tag(view, "campo")`. Cuando el back lo genere, el
  front lo toma solo, sin tocar las páginas. Con `SOC_EXAMPLES=0` se ve únicamente lo que da el back.
- **Los valores de ejemplo salen de reglas de prueba** (`scripts/nivel1_triage.py`). Sirven para diseñar todos los
  estados, no son el criterio final.
- **Los textos de la alerta los escribe a veces el atacante.** Nunca se pintan como HTML: usad `ui.md()`,
  `st.text`, `st.code` o `st.json`.

Eventos del directo (`data.run_triage(ids, on_event)`): `alert_started` → un `api_call` por consulta → `verdict`
con el resultado completo → al final, `done`. Hoy las consultas llegan al terminar cada alerta, porque el back aún
no avisa paso a paso.

## Paso 0: ya está hecho, solo hay que bajarlo

El esqueleto ya está en GitHub, en `perebranch`, con dos ramas preparadas: `front-a` y `front-b`. La app arranca
con datos y los tests pasan.

1. Bajar el repo y cambiar a tu rama:
   - `git clone https://github.com/perepages/hackathondeloitte.git` (o `git fetch` si ya lo tienes)
   - persona A: `git checkout front-a` · persona B: `git checkout front-b`
2. Preparar el entorno (vale Python 3.10 o superior): `python -m venv .venv` y después
   `.venv\Scripts\python.exe -m pip install -r requirements.txt`.
3. Arrancar la app: `.venv\Scripts\python.exe -m streamlit run app.py` y abrir http://localhost:8501. No necesita
   la API: lee `data/fixture.json`.
4. Comprobar que todo funciona: `.venv\Scripts\python.exe -m pytest -q` (19 tests).
5. Cada página empieza con un comentario con sus TODO. A empieza por `views/cola.py`; B, por `views/directo.py`.
6. Solo para el modo live o para regenerar el fixture: dataset de Deloitte en `../DTT-UAB-The-Hack` y su API
   arrancada (`python -m uvicorn mock_soc_api:app --port 8000` desde `06_herramientas`). Para regenerar:
   `.venv\Scripts\python.exe scripts/build_fixture.py`.

## Persona A: el analista

A enseña **una alerta en profundidad**: qué detectó, qué consultó el sistema, por qué decidió lo que decidió y
dónde decide la persona. A también es dueño de `app.py` y `core/ui.py`, que usan los dos.

### `core/ui.py` (lo primero, porque B lo importa)

Paleta fija; no se inventan colores nuevos:

| Qué | Valor | Color |
| --- | --- | --- |
| Veredicto | `false_positive` | `#2a78d6` azul |
| Veredicto | `true_positive` | `#eb6834` naranja |
| Veredicto | `benign_true_positive` | `#1baf7a` aqua |
| Veredicto | `needs_more_info` | `#eda100` amarillo |
| Severidad | `critical` · `high` · `medium` · `low` · `informational` | `#d03b3b` · `#ec835a` · `#e0a514` · `#7f97b2` · `#a7adb7` |

Funciones:

- `VERDICT_LABEL`, `SEVERITY_LABEL`: textos en castellano («Falso positivo», «crítica»…).
- `verdict_badge(v)` y `severity_badge(s)`: devuelven la etiqueta de color lista para
  `st.markdown(…, unsafe_allow_html=True)`. Solo llevan texto nuestro, nunca texto de la alerta.
- `severity_matrix(rule_sev, criticality)`: `DataFrame` de la matriz §2 de la política con `Styler` que resalta
  la celda aplicada.
- `data.summarize_query(query, contexts)`: convierte una consulta en una frase («WS-BCN-1174 · criticidad Alta ·
  zona HQ-USERS»). Ya existe.
- `query_list(queries)`: pinta la lista de consultas con un punto verde (ok), amarillo (no encontrado) o rojo (error).

### Página `views/cola.py`

Qué muestra:

- **Arriba, la cola:** `st.dataframe` con hora, regla, producto, severidad, veredicto, decisión y si está revisada.
  Filtros encima en una fila: decisión (todas / a escalar / a cerrar), veredicto y búsqueda de texto. Al
  seleccionar una fila (`on_select="rerun"`, `selection_mode="single-row"`) se abre el detalle.
- **Debajo, el detalle en 5 pasos** (`st.container(border=True)` cada uno):
  1. *Qué detectó la regla:* descripción, entidades (hosts, usuarios, IPs, dominios) y evidencia.
  2. *Qué consultó el sistema:* `ui.query_list`. Botón «Repetir la investigación» que las muestra una a una con
     `time.sleep(0.3)`.
  3. *Veredicto:* etiqueta, confianza con `st.progress` y justificación.
  4. *Severidad final:* `severity_matrix` + `severity_rationale`.
  5. *Decisión de la persona:* «El sistema propone: Cerrar / Escalar a N2», campo con el nombre del analista, nota
     opcional y dos botones, «Aceptar» y «Corregir». Se guarda con `store.save_review(...)`.
- **Avisos:** `st.warning` si hay `injection_flags` y una caja «Lo que no he podido resolver» con `open_questions`.

Hecho cuando: cualquiera de las 150 alertas muestra los 5 pasos sin error, y la decisión sigue ahí tras reiniciar
la app.

### Página `views/ticket.py`

Qué muestra: la ficha que recibe el N2, en el formato de `01_contexto/ticket_salida.schema.json`: título,
veredicto y confianza, severidad con su razón, afectados, resumen, evidencias, enriquecimiento, MITRE, acciones
recomendadas (marcando cuáles requieren aprobación), escalado y preguntas abiertas.

Función: `build_ticket(result) -> dict`, que traduce nuestro resultado al esquema de Deloitte. Botón
`st.download_button` para bajar el JSON.

Hecho cuando: el JSON descargado de cualquier alerta valida contra el esquema con `jsonschema`.

### Página `views/contencion.py` (nivel 4, solo si hay tiempo)

Qué muestra: para las alertas escaladas, las `recommended_actions` en tres estados: propuesta, aprobada y
ejecutada. Para aprobar hacen falta el nombre del analista y el motivo, y luego se ejecuta. Llama a
`data.approve(...)` y `data.contain(...)`, que hace B.

Reglas de la política que se ven en pantalla:

- `block_ioc` y `purge_email` no necesitan aprobación.
- El resto sí.
- Las acciones sobre la red OT están deshabilitadas, con el texto «Escalar a Operaciones».

Hecho cuando: una acción ejecutada aparece en `GET /containment/log` de la API simulada.

## Persona B: la operación

B enseña **todas las alertas a la vez y el paso del tiempo**: cómo entran y se resuelven en directo, el valor
para el negocio y los SLA. B también es dueño de `core/data.py` y `core/store.py`, así que es quien habla con la
persona del back.

### `core/data.py` (ya funciona; A lo importa)

- `load_results() -> list[dict]`: resultados de triaje con la decisión de la persona ya unida.
- `get_result(alert_id) -> dict | None`.
- `run_triage(alert_ids, on_event)`: tría una lista y va llamando a `on_event` con los eventos del contrato. En
  modo fixture reproduce las consultas del fixture con pausas de 0,35 s.
- `load_alert_ids_from_jsonl(content) -> list[str]`: lee el JSONL que nos den el último día.
- `approve(action, target, approver, reason) -> token` y `contain(action, target, justification, token) -> dict`:
  para el nivel 4. Simulados en modo fixture.
- El modo se elige con la variable de entorno `SOC_MODE=fixture` (por defecto) o `SOC_MODE=live`.

### `core/store.py` (ya funciona)

SQLite en `data/soc.db`. Tabla `reviews(alert_id, decision, analyst, note, at)` y funciones `save_review`,
`get_review`, `list_reviews` y `delete_review`. El fichero `data/soc.db` no se sube a git (`*.db` en `.gitignore`).

### Página `views/directo.py`

Qué muestra:

- **Entrada:** `st.file_uploader` para un JSONL, un `st.text_area` para pegar IDs y, sin entrada, 10 de ejemplo
  (5 que se cierran y 5 que se escalan, de reglas distintas).
- **Botón «Iniciar triaje»** y barra `st.progress` con «N de 10 alertas triadas».
- **Kanban** en 4 `st.columns`, cada una con un `st.empty()` que se repinta en cada evento: Entrantes,
  Investigando, Cerradas por el sistema y Esperan a la persona. Esta última columna va resaltada.
- En la tarjeta que se está investigando van apareciendo las consultas (ruta + frase de `summarize_query`). Las
  tarjetas resueltas llevan veredicto y severidad.
- **Al acabar:** resumen (cuántas cerradas, cuántas esperan a la persona) y botón «Abrir en la cola» para cada una
  que espera, que lleva a la página de A.

Hecho cuando: subir un JSONL de 10 alertas las tría en menos de 1 minuto, y después se ven en la cola.

### Página `views/panel.py`

Qué muestra (gráficos con Altair y la paleta de `core/ui.py`):

- 4 `st.metric`: alertas triadas, % cerradas por el sistema, escaladas a N2 y horas de analista ahorradas. Esta
  última con el supuesto escrito: 8 min por alerta manual.
- Reparto por veredicto: una barra al 100 %.
- Veredicto por regla: barras horizontales apiladas, las 9 reglas con más alertas y «Otras».
- Severidad de la regla frente a severidad final: mapa de calor con el recuento en cada celda.
- Alertas por día: barras apiladas, cerradas y escaladas.
- **SLA de las escaladas:** tabla con el tiempo que queda según la política (crítica 15 min, alta 30 min, media
  4 h, baja 24 h), actualizada con `@st.fragment(run_every="10s")`. Las vencidas, en rojo.

Hecho cuando: los números cuadran con los filtros de la cola y la tabla de SLA se actualiza sola.

### Página `views/incidentes.py` (niveles 2-3, solo si hay tiempo)

Qué muestra: alertas agrupadas por `incident_id` en tarjetas de incidente (alertas, entidades compartidas,
severidad máxima) y una línea temporal Altair de cada incidente con sus fases MITRE. Mientras el back no genere
`incident_id`, se usa el incidente de ejemplo del fixture (`INC-EJ-001`), marcado como ejemplo en pantalla.

Hecho cuando: un incidente con 3 o más alertas se ve como una sola historia.

## Reglas para no pisarse

- **Cada fichero tiene un dueño** (tabla de Arquitectura). Si necesitas un cambio en un fichero del otro, avisa y
  hazlo en un commit pequeño con un mensaje claro.
- **Claves de `st.session_state` con prefijo** de la página: `cola_`, `ticket_`, `directo_`, `panel_`. La única
  clave compartida es `selected_alert`.
- **Una sola forma de ir a una alerta desde otra página:** `st.session_state["selected_alert"] = alert_id` y
  después `st.switch_page("views/cola.py")`. La cola abre esa alerta al cargar.
- **Las páginas no leen ficheros ni llaman a la API de Deloitte.** Siempre pasan por `core/data.py`.
- **El fixture manda.** Si necesitas un campo nuevo, añádelo primero al fixture con un ejemplo y apúntalo en la
  tabla del contrato. Después lo pintas.
- **El texto de las alertas nunca se pinta como HTML.** Lo escribe a veces el atacante.
- **Ramas `front-a` y `front-b`**, con `merge` a `perebranch` al menos una vez al día, con los tests en verde.
- **La interfaz, en castellano**, porque el jurado es de Deloitte.
- **Nada de colores ni formatos nuevos fuera de `core/ui.py`.** Si falta algo, se añade allí.

## Integración con el back

Ya está enlazado: con `SOC_MODE=live`, `core/data.py` llama a `triage.analyze_alert()` del back contra la API
:8000. Las páginas no cambian.

| Función de `core/data.py` | Modo fixture (por defecto) | Modo live |
| --- | --- | --- |
| `load_results()` | Lee `data/fixture.json` | Resultados triados en la sesión |
| `analyze_live(id)` | — | `triage.analyze_alert(id)` y después `to_view()` |
| `run_triage(ids, on_event)` | Reproduce las consultas del fixture con pausas | Analiza cada alerta y emite sus consultas al terminarla |
| `approve()` / `contain()` | Simulados | `POST /approvals` y `POST /containment/{acción}` |

Lo que falta del back (hay que pedírselo a su equipo):

1. **Veredicto real** (`true_positive`, `benign_true_positive`, `false_positive`) con justificación y confianza.
   Hoy siempre devuelve `needs_more_info`.
2. **`decision`** (`close` o `escalate`), `title`, `summary` y `recommended_actions`.
3. **Detectar la inyección** (`injection_flags`). El correo `ALR-20261020-011905` lleva texto oculto que pide
   clasificarlo como falso positivo y no escalarlo; hoy el back no lo marca y le da severidad baja.
4. **Un `on_event` en `analyze_alert`**, para que el directo muestre las consultas en tiempo real.
5. **Mantener los nombres de los campos de `TriagePreview`.** Si cambian, avisar a B, que adapta `to_view()`.
6. **Funcionar sin LLM:** si no hay clave o el modelo falla, el resultado tiene que seguir saliendo.

La clave del LLM de la UAB no la usa el front: la usa el back y va en `.env`, que no se sube a git.

## Orden de trabajo y checklist final

Se trabaja en 4 bloques. No se empieza el bloque 4 (niveles 2-4) hasta que los bloques 1-3 funcionen de principio
a fin: un nivel 1 sólido vale más que llegar al 4 sin poder demostrarlo.

| Bloque | Persona A | Persona B | Back |
| --- | --- | --- | --- |
| 1 · Base (hecho) | Esqueleto `app.py`, `core/ui.py`, cola | Fixture, `core/data.py`, `core/store.py` | — |
| 2 · Pantallas | Detalle en 5 pasos, decisión, ticket + JSON | Directo (simulado), panel de negocio | Veredicto, `on_event`, campos nuevos |
| 3 · Enlace con el back | Aviso de inyección, preguntas abiertas, probar en live | `SOC_MODE=live`, directo real, SLA | — |
| 4 · Si hay tiempo | Contención (nivel 4) | Incidentes (niveles 2-3) | — |

Los bloques 1 y 2 no esperan al back; el 3 empieza cuando el motor emite eventos y los campos nuevos.

Antes de la defensa, todo esto tiene que estar comprobado:

- [ ] La app arranca con un solo comando y abre las páginas sin errores.
- [ ] Se sube un JSONL de 10 alertas en En directo y se trían en menos de 1 minuto.
- [ ] Cada alerta muestra los 5 pasos: qué detectó, qué consultó, veredicto, severidad y decisión.
- [ ] La decisión de la persona queda guardada con su nombre y se ve en la cola.
- [ ] El ticket descargado valida contra el esquema de Deloitte.
- [ ] Los avisos de inyección y «Lo que no he podido resolver» salen cuando toca.
- [ ] El panel cuadra con la cola, y el supuesto de horas ahorradas se ve escrito.
- [ ] Todo funciona sin internet y sin LLM (modo reglas).
- [ ] Hemos ensayado la historia de 5 pasos de la presentación de principio a fin.
