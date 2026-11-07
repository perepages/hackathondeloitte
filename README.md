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
