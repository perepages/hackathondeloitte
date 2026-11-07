# Tarvia SOC — MVP de triaje asistido

Aplicación local para visualizar alertas de la API simulada del reto Deloitte/UAB, recopilar contexto y aplicar la matriz de severidad del SOC.

## Requisitos

- Python 3.12
- API simulada del reto activa en `http://127.0.0.1:8000`

## Instalación (Windows / PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Arranca primero la API simulada desde `DTT-UAB-The-Hack/06_herramientas` según su `LEEME_herramientas.md`. Déjala ejecutándose en otra ventana.

Después, desde la raíz de este repositorio:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

La interfaz se abrirá en `http://localhost:8501`.

## Pruebas

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Alcance actual

La primera versión muestra alertas, consulta detalles y contexto en la API simulada y calcula la severidad base con la matriz publicada. No ejecuta contención ni utiliza todavía un modelo LLM; las decisiones se presentan como preliminares para revisión humana.

## Frontend (Streamlit, dos personas)

Plan completo: [Plan de frontend en Streamlit](https://claude.ai/artifact/1qah4Mo2UYyjNkucHodzVA).
Funciona también con Python 3.10.

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py          # datos del fixture, sin API
$env:SOC_MODE="live"; .\.venv\Scripts\python.exe -m streamlit run app.py   # back real (API :8000)
.\.venv\Scripts\python.exe -m pytest -q                    # incluye tests/test_front_pages.py
```

| Carpeta / fichero | Dueño | Qué es |
| --- | --- | --- |
| `app.py`, `core/ui.py` | A | Navegación, colores, etiquetas, matriz |
| `views/alertes.py`, `views/informe_n2.py`, `views/accions_resposta.py` | A | Una alerta en profundidad y la decisión humana |
| `core/data.py`, `core/store.py` | B | Única puerta a los datos (traduce el `TriagePreview` del back al contrato del front) y decisiones en SQLite |
| `views/triatge_directe.py`, `views/resum.py`, `views/incidents.py` | B | Directo, panel de negocio, incidentes |
| `views/prototip_back.py` | back | Primera app del back, conservada como referencia |
| `data/fixture.json` | B | 150 alertas: salida real del back + `_ejemplo` con los campos que el back aún no genera |
| `scripts/build_fixture.py` | B | Regenera el fixture (necesita la API :8000) |
| `demo/triaje_demo.html` | — | Maqueta HTML de referencia visual |

**Contrato:** las páginas solo usan el diccionario que devuelve `core.data.to_view()` (documentado al principio
de `core/data.py`). Los valores que vienen de `_ejemplo` se listan en `example_fields` y la interfaz los marca
como «dato de ejemplo». Con `SOC_EXAMPLES=0` se ve solo lo que da el back.

**Ramas:** persona A trabaja en `front-a`, persona B en `front-b`; ambas salen de `perebranch` y se fusionan
en `perebranch` al menos una vez al día, con los tests en verde.

## Plan de acción con IA (`assistant.py`)

En **Alertas**, el recuadro «Borrador del plan de acción» pide a un LLM un resumen y de 3 a 5 acciones. Es la
«Integració LLM» del back, generalizada: funciona con la pasarela LLM del equipo (compatible con OpenAI) o con
Ollama local, y también se usa en la página «Prototipo del back». Configuración en `.env` (ver `.env.example`; la
clave **no** se sube a git). Sin LLM configurado, el resto funciona igual.

- Los datos de la alerta se pasan al modelo entre `<datos_no_fiables>` y el mensaje de sistema prohíbe obedecer
  instrucciones que vengan ahí (probado con el correo `ALR-20261020-011905`, que intenta forzar un falso positivo).
- El modelo solo redacta: no cambia el veredicto, la gravedad ni ejecuta acciones.
- Con el modelo `ornith` de la pasarela el razonamiento va desactivado por defecto (~6 s por respuesta en vez de ~30 s);
  `LLM_REASONING=1` lo activa.
