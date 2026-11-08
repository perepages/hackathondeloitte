# Estado actual del proyecto · Triaje N1 Tarvia (reto Deloitte × UAB The Hack)

8 nov 2026 · rama `perebranch` = `main` (incluye `11a4b0a` de Marc: radio sí, su cambio de gravedad revertido) · **159 tests en verde** · túnel DNS con criterio firme RB-09 · contención envía `ticket_id` · castellanismos corregidos (`fix_slips`) · Streamlit 1.65

## 1. En una frase

App Streamlit (interfaz en catalán) que hace el **triaje de nivel 1** del SOC de Tarvia: lee cada alerta, agrupa las
repeticiones del mismo evento, investiga con la API de Deloitte, la IA propone si es un ataque, las reglas de los
runbooks dan una segunda opinión y la **política del SOC fija la gravedad y si se cierra o se escala**. Una persona
decide al final. Funciona en **modo muestra** (150 alertas ya triadas, sin red) y en **modo directo** (alertas nuevas,
con la API y la IA).

## 2. Repositorio

| Rama | Estado |
| --- | --- |
| `perebranch` | La buena. Todo lo de abajo. |
| `main` | Idéntica a `perebranch` (se hace *fast-forward* en cada push). |
| `pozobranch` (Marc) | **No se usa.** Su lógica de runbooks se portó a `rules.py` con los errores corregidos; su `app.py` era la app antigua. |
| `Prova_LLM` (Martí) | **No se usa.** Experimento sobre el `main` antiguo; duplicaba lo que hace `verdict.py`. |
| `front-a`, `front-b` | Antiguas, ya fusionadas. |

Fuera de git en la copia local: `demo/triaje.json` aparece **borrado sin commit** (no lo hemos tocado nosotros;
`git checkout demo/triaje.json` lo recupera) y `PLAN_INDIVIDUAL.md` (plan personal, sin subir).

## 3. Cómo arrancarlo

```powershell
# instalar (una vez)
python -m venv .venv; .venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env          # y poner LLM_API_KEY

# modo muestra (por defecto): 150 alertas ya triadas, sin API ni IA
.venv\Scripts\python.exe -m streamlit run app.py

# modo directo: primero la API de Deloitte (FastAPI y uvicorn ya están en requirements.txt)
#   desde DTT-UAB-The-Hack\06_herramientas:
..\..\hackathondeloitte\.venv\Scripts\python.exe -m uvicorn mock_soc_api:app --port 8000
#   y la app (o poner SOC_MODE=live en el .env, que ahora sí se lee):
$env:SOC_MODE="live"; .venv\Scripts\python.exe -m streamlit run app.py

# tests
.venv\Scripts\python.exe -m pytest -q
```

En modo directo la app empieza vacía: las alertas entran por **Triatge en directe** (subir un `.jsonl`, pegar ids o las
10 de ejemplo de la cola) o por **Alertes → Actualitzar alertes** (5 nuevas de la cola por clic). La barra lateral dice
el modo: «Mostra de 150 alertes del repte» o «Connectat a l'API del SOC».

## 4. Arquitectura y recorrido de una alerta

```
                ┌──────────── front (Streamlit, catalán) ────────────┐
 app.py ──► views/*.py ──► core/ui.py (lenguaje claro, colores, componentes)
                │
                ▼
          core/data.py  ← ÚNICA puerta a los datos (contrato del front en su docstring)
           │   modo muestra: lee data/fixture.json
           │   modo directo: run_triage()
           ▼
 1. _fetch_alert   soc_api.get_alert (la API es la fuente de verdad; si no la reconoce → se salta y se avisa)
 2. correlation.correlate   agrupa el mismo evento repetido (ventana SOC_DEDUP_WINDOW_MIN)
 3. _triage_one    triage.analyze_alert(alert) — 4 a la vez (SOC_WORKERS)
       ├─ evidencias: inventario, usuario + su puesto, servicio afectado, inteligencia, sandbox,
       │  cambios (por equipo y citados en la evidencia), registros ±24 h
       ├─ gravedad base: policy.base_severity (matriz §2) con el activo más crítico
       └─ verdict.decide
             ├─ assistant.decide_json  → la IA propone el VEREDICTO (JSON, datos como no fiables)
             ├─ rules.evaluate        → runbooks + reglas por caso de uso (respaldo y segunda opinión)
             └─ política (siempre): texto oculto, ajuste ±1 por hechos, cerrar/escalar, acciones, OT
 4. to_view        → contrato del front; se guarda en la sesión (data_live_results)
                ▼
 la persona decide (core/store.py → data/soc.db)  ·  informe N2 validado contra ticket_salida.schema.json
```

## 5. Archivos

### Back (raíz)

| Archivo | Qué hace | Origen |
| --- | --- | --- |
| `soc_api.py` | Cliente HTTP de la API simulada de Deloitte (`SOC_API_URL`). | Marc |
| `schemas.py` | Modelos Pydantic: `Alert` (acepta campos extra, p. ej. `group`), `TriagePreview` con la propuesta completa (`verdict`, `confidence`, `decision`, `recommended_actions`, `injection_flags`, `decision_source`, `decision_notes`, `rule_applied`, `second_opinion`…). | Marc + nuestro |
| `policy.py` | Matriz de gravedad §2 (comprobada celda a celda contra `politica_soc.md`), ajuste ±1, activo afectado cuando la alerta no trae equipo (`service_assets`, `cloud_asset`), nombres en catalán (`SEVERITY_CA`, `criticality_ca`). | Marc + nuestro |
| `triage.py` | `analyze_alert(alert_id, decide=True, alert=None)`: recoge evidencias y calcula la gravedad base. Busca el activo afectado (equipo → puesto del usuario → servicio/bucket) y los cambios citados en la evidencia (`CHG-…`). | Marc + nuestro |
| `correlation.py` | **Correlación / deduplicación de nivel 1** (ver §6.1). | nuestro (8 nov) |
| `incidents.py` | **Incidentes de nivel 2** (ver §6.4): alertas distintas de la misma intrusión, un ticket. | nuestro (8 nov) |
| `verdict.py` | `decide()`: une IA + reglas + política (ver §6.2). También `plain_text` (quita códigos internos de los textos de la IA), `fact_adjustment`, `blocked_by_control`, normalización de acciones. | nuestro |
| `guard.py` | **Defensa ante manipulación (prompt injection)**, ver §6.3: limpieza antes de la IA, detector ampliado, objetivos de acciones, citas inventadas, Markdown seguro. | nuestro (8 nov) |
| `rules.py` | Motor de reglas: runbooks RB-01…RB-10 de Marc **con 9 errores corregidos** + reglas por caso de uso + regla nueva RB-03 de VPN de proveedor. Respaldo si falla la IA y segunda opinión visible. | Marc (lógica) + nuestro |
| `assistant.py` | Todo lo del LLM: configuración (pasarela UAB `ornith` u Ollama), `decide_json` (veredicto en JSON) y `action_plan` (borrador del plan, en streaming). Los prompts piden **catalán**, tratar los datos como no fiables y no citar campos internos. | nuestro (idea de Martí) |
| `scripts/nivel1_triage.py` | Reglas por caso de uso originales (las usa `rules.py`). | nuestro |
| `scripts/build_fixture.py` | Regenera `data/fixture.json`: lee las 150 alertas de la muestra, **las agrupa**, las tría con el back y compara con las reglas (`--out`, `--reference`, `--workers`). | nuestro |

### Front

| Archivo | Página / función |
| --- | --- |
| `app.py` | Navegación, logo «Tarvia SOC», modo en la barra lateral. Oculta «Prototip del back» salvo con `SOC_DEV=1`. |
| `core/data.py` | Única puerta a los datos: `to_view`, `load_results`, `run_triage` (leer → agrupar → triar en paralelo, eventos para el kanban), `parse_alert_file` (salta líneas rotas), `refresh`, `suggest_ids`, aprobación/contención, LLM. |
| `core/ui.py` | Etiquetas en lenguaje claro, colores validados para daltonismo, distintivos, matriz, tabla de entidades (listas, objetos `cloud`, texto `ai_session`), radio dibujado de la bandeja, tarjetas del kanban, `group_count`. |
| `core/store.py` | SQLite con la decisión de la persona (quién, cuándo, si corrigió al sistema, nota). |
| `views/inici.py` | Inici: qué es, flujo en 4 pasos, cifras, recorrido. |
| `views/alertes.py` | Alertes: bandeja (botón «Actualitzar alertes», selección con radio, filtros, columna «Agrupa») + ficha (5 pasos, segunda opinión de las reglas, notas de la política, aviso de alertas agrupadas, plan de la IA, decisión). |
| `views/informe_n2.py` | Informe per a N2 en formato Deloitte, validado y descargable; lleva todos los `alert_ids` del grupo. |
| `views/accions_resposta.py` | Lista con un desplegable por alerta; ordenar (gravedad, fecha, pendientes, N2, tipo) y filtrar; aprobar/ejecutar (simulado en muestra). |
| `views/triatge_directe.py` | Kanban en directo (varias en «Investigant», tarjetas agrupadas, avisos de alertas saltadas, tarjetas de escaladas con la gravedad nueva). |
| `views/resum.py` | Cifras, gráficos, mapa de gravedad, SLA. |
| `views/incidents.py` | Incidents: tarjeta por incidente (pistas compartidas, por qué se escala), tabla y línea temporal MITRE (de Adri). |
| `views/prototip_back.py` | Oculta (solo `SOC_DEV=1`). |

### Datos, configuración y tests

- `data/fixture.json`: las 150 alertas triadas (modo muestra). `data/comparacion_veredictos.json`: IA vs reglas. `data/soc.db`: decisiones (no se sube).
- `.env.example`: `SOC_API_URL`, `LLM_*`, `SOC_DEDUP_WINDOW_MIN`. `.streamlit/config.toml`: tema.
- `tests/` (82): `test_correlation`, `test_verdict`, `test_rules`, `test_policy`, `test_triage`, `test_ingesta`, `test_front_pages`, `test_assistant`, `test_soc_api`. `conftest.py` fuerza `SOC_VERDICT_ENGINE=rules` (sin red).
- Fuera del repo: `..\.claude\launch.json` con `front-streamlit` (8501, muestra), `front-directe` (8502, directo), `api-deloitte` (8000) y `fitxers-prova` (8090, sirve `03_alertas` para pruebas de subida).

## 6. Cómo decide

### 6.1 Correlación de nivel 1 (antes de la IA)
Dos alertas son el mismo evento si tienen **la misma regla**, la segunda llega **dentro de la ventana contada desde la
primera** (`SOC_DEDUP_WINDOW_MIN`, 5 min; 0 desactiva) y comparten **datos clave**: mismo sujeto (equipo, usuario,
cliente o bucket) y mismo indicador (IP, dominio, remitente o hash) cuando las dos los tienen. La agrupada conserva
id y hora de la primera, une sin duplicados `related_events` y entidades, toma la gravedad de regla más alta y lleva
`group = {count, alert_ids, first_seen, last_seen, window_min, shared_keys}`. Dataset completo: 13 grupos (56 alertas)
con 5 min; la muestra de 150 no tiene ninguno.

### 6.2 Veredicto, gravedad y decisión (estable)
1. **La IA propone solo el veredicto** (ataque real / autorizada / falsa alarma / falta información) y redacta.
2. **Texto oculto** para el clasificador → siempre ataque real y escalar.
3. **Gravedad** = matriz §2 (regla × activo más crítico) ± ajuste **calculado con hechos**, nunca con la opinión de la
   IA: −1 si un control lo bloqueó, +1 si un runbook confirma acceso o ejecución, +1 VIP; máximo ±1. Autorizada o
   falsa alarma → informativa o baja.
4. **Cerrar/escalar** por reglas fijas: escalar si ataque real de gravedad media o más, falta información en media o
   más, texto oculto, criterio obligatorio de un runbook (fraude, credenciales, ejecución…) o **conclusión dudosa**
   (IA y reglas no coinciden en si es un ataque; la seguridad se limita al 50 %). El resto se cierra.
5. **Acciones**: purgar correo y bloquear IOC sin aprobación; el resto N2; nada sobre OT; uso dual con N2.

Calendario de cambios en **hora de España** (convertido a UTC). Si la IA falla, deciden las reglas.

### 6.4 Incidentes de nivel 2 (`incidents.py`, después del triaje)
Política §1.4 (correlacionar), §5 (escalar cadenas aunque cada alerta sea baja) y §6 (un ticket por intrusión con todos
los `alert_ids`). Se calcula en `core/data._with_incidents` al cargar los resultados (muestra y directo).
- **Entran** las alertas de ataque real, falta información o escaladas (lo autorizado no forma incidentes).
- **Unen** las pistas compartidas: indicador del atacante (IP externa, dominio, hash, remitente, message_id, sesión IA;
  30 días), cuenta (14 días) y equipo / IP interna (48 h), en cadena. **No unen** la gravedad, la criticidad ni el tipo
  de regla; ni dominios propios, servicios legítimos, proveedor legítimo, ni pistas en más de 25 alertas.
- **Decisión**: se escala si alguna alerta se escalaba o si es cadena (≥ 2 reglas distintas de ataque); entonces las
  alertas que solas se cerraban pasan a escalar con nota (§5). Gravedad = la más alta de sus alertas.
- **Informe N2**: una alerta de un incidente lleva al ticket `TKT-INC-…` del incidente entero (formato `ticket_salida`).
- **Medido**: 138 alertas de escenario → 14 incidentes (84 alertas) que coinciden con las historias del reto; ninguna
  autorizada dentro; muestra de 150 → 8 incidentes (21 alertas). Peor caso (las 11 061 tratadas como ataque): el
  incidente más grande, 79 alertas.

### 6.3 Defensa ante manipulación (`guard.py`)
La base es de arquitectura: la IA solo propone y redacta; la política decide. Encima:
1. **Limpieza antes de la IA** (`sanitize`): quita caracteres invisibles, normaliza letras disfrazadas (NFKC) y
   neutraliza etiquetas falsas (`</datos_no_fiables>`, `SYSTEM:`, `<|…|>`). Detrás de los datos va un recordatorio.
2. **Detector** en toda la alerta (no solo `evidence`), castellano/catalán/inglés. Dos tipos: `instruccio` (órdenes →
   ataque real y escalar) y `ocultacio` (texto escondido → escalar). UC-AI-001: las frases del cliente al asistente
   solo cuentan si van dirigidas al clasificador. Ver abajo.
3. **Acciones**: un objetivo que no sale en los datos, o que no es del tipo que pide la acción (cuenta, equipo, indicador, correo, clave cloud), se descarta; bloquear un dominio propio, IP interna, equipo del
   inventario, proveedor legítimo o servicio conocido pide N2; con cualquier sospecha, todo pide N2.
4. **Citas**: si la IA cita CHG/tickets/IPs/correos que no existen, nota; y si con eso cierra, se escala.
5. **Pantalla**: el texto de la IA se pinta sin imágenes (exfiltración), sin enlaces clicables ni HTML.
El detector revisa también los registros relacionados (el texto completo del RAM scraper de los TPV, `ALR-20261020-011897..899`, solo está en el log del EDR). Dataset: 15 alertas trampa (12 correos + 3 TPV), 0 falsas alarmas.
Tests: `tests/test_injection.py` (29 alertas trampa). Sobre las 138 alertas de escenario (ids ≥ 011785) la IA acierta 131/135 ataque sí/no y no cierra ningún ataque.

## 7. Qué funciona (comprobado)

- **Muestra (150)**: 127 cerradas y 23 escaladas; 65 ataques reales; activo afectado encontrado en 145/150; IA y reglas
  coinciden en 134/150; 5 dudosas escaladas; todo en catalán y sin códigos internos.
- **Estabilidad**: las mismas 10 alertas triadas 3 veces con la IA real dan la misma gravedad y decisión.
- **Los 41 tipos de alerta** del dataset (20 fuera de la muestra), triados en directo: todas las pantallas, fichas e
  informes funcionan; entidades `cloud` y `ai_session` bien mostradas.
- **Subida de JSONL** (`alertas_100.jsonl`): 100 alertas en ~4,5 min con la IA, 4 a la vez; líneas rotas y alertas
  desconocidas se saltan con aviso «X alertes s'han saltat per algun error» sin parar el lote.
- **Correlación en directo**: 14 alertas → 7 casos (bucket ×5, pentest ×2, lateral ×2, SCCM ×2), una llamada a la IA
  por grupo.
- **Seguridad ante el atacante**: el texto de las alertas nunca se pinta como HTML; el correo
  `ALR-20261020-011905` con texto oculto se detecta y se escala.

## 8. Variables de entorno

| Variable | Por defecto | Para qué |
| --- | --- | --- |
| `SOC_MODE` | `fixture` | `live` = modo directo |
| `SOC_API_URL` | `http://127.0.0.1:8000` | API de Deloitte |
| `SOC_WORKERS` | 4 | alertas triadas a la vez |
| `SOC_DEDUP_WINDOW_MIN` | 5 | ventana de correlación (0 = sin agrupar) |
| `SOC_VERDICT_ENGINE` | `auto` | `rules` = sin IA (rápido) |
| `SOC_EXAMPLES` | 1 | `0` quita los campos de ejemplo del fixture |
| `SOC_INCIDENT_DAYS` / `_ACCOUNT_DAYS` / `_HOST_HOURS` / `_HUB` | 30 / 14 / 48 / 25 | incidentes de nivel 2 (§6.4) |
| `SOC_DEV` | 0 | `1` enseña «Prototip del back» |
| `LLM_PROVIDER/BASE_URL/API_KEY/MODEL` | pasarela UAB, `ornith` | IA |

## 9. Bugs y limitaciones pendientes

**Bugs arreglados el 8 nov** (antes estaban aquí)
1. ~~`SOC_MODE`, `SOC_EXAMPLES`, `SOC_WORKERS` no se leían del `.env`~~: `app.py` y `core/data.py` lo cargan primero.
2. ~~La IA a veces responde en castellano~~ (~4 %, 6 de 138): `assistant.ensure_catalan` lo detecta y pide SOLO una
   traducción (no vuelve a decidir; ~2 s más). Lo mismo para el plan de acción. `plain_text` atrapa también
   `cobre_esta_alerta` (la IA lo escribe mal).
3. ~~`requirements.txt` sin FastAPI ni uvicorn~~: añadidos; la API arranca con el Python del proyecto.
4. ~~Las acciones `disable_account` y `disable_cloud_keys` no existían en la API de Deloitte~~ («acción no soportada»):
   `core/data.api_action` las traduce a `disable_user` y `disable_access_key`.

**Limitaciones**
4. En un caso de verdad dudoso, **la IA puede cambiar de veredicto entre sesiones** (p. ej. la subida a WeTransfer
   `ALR-20261014-004075`); con el mismo veredicto el resultado ya es fijo. Mejora posible: votar 3 veces (3× lento).
5. Los resultados en directo **viven en la sesión del navegador**: recargar la página los pierde.
6. **Incidentes sin relacionar entre sí** (nivel 3): el túnel DNS de WMS01 y la VPN de Logisoft (su proveedor) no comparten pista directa y quedan como dos incidentes; el informe de incidente de N2 (`informe_incidente.schema.json`) no se genera.
7. El kanban muestra las consultas al **terminar** cada alerta, no en tiempo real (falta `on_event` en el back).
8. «Seguretat de la conclusió» es la **autoestimación de la IA** (o un valor fijo de la regla), no una probabilidad
   calibrada.
9. Las 10 alertas de ejemplo del directo son **siempre las mismas** (misma posición de la cola).
10. Avisos de Streamlit por funciones obsoletas (`use_container_width`, `components.html`); funcionan, pero habrá
    que cambiarlas al actualizar Streamlit.
11. Casos discutibles para revisar a mano: túnel DNS hacia `e5.sk` (podría ser ESET); alguna regla muy concreta
    heredada (`gestoria-pons.example`).
12. Restos: `assets/deloitte_logo_blanco.png` ya no se usa; `docs/PLAN_FRONTEND.md` está desfasado.

## 10. Siguiente paso

Incidentes de nivel 2 hechos (§6.4). Posibles siguientes: relacionar incidentes (nivel 3, `related_incidents`), generar
el `informe_incidente` para N2 (paciente cero, línea temporal, alcance) y los bugs del §9.

**Otros pendientes para la defensa**: probar en directo con alertas nuevas justo antes, preparar el guion de la demo
y ensayarlo, y decidir con el equipo los casos discutibles del §9.
