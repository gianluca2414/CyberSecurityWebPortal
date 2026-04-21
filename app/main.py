from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.services.abuseipdb import AbuseIPDBError, check_ips
from app.services.catalog import build_catalog_links
from app.services.investigation import InvestigationError, investigate_target

BASE_DIR = Path(__file__).resolve().parent
settings = get_settings()

app = FastAPI(title=settings.app_title)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def build_common_context(request: Request):
    return {
        "request": request,
        "app_title": settings.app_title,
        "has_abuseipdb": bool(settings.abuseipdb_api_key),
        "has_vt": bool(settings.virustotal_api_key),
        "has_shodan": bool(settings.shodan_api_key),
        "has_otx": bool(settings.alienvault_otx_api_key),
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, q: str | None = None):
    context = build_common_context(request)
    context.update(
        {
            "catalog_query": q or "",
            "catalog": build_catalog_links(q),
        }
    )
    return templates.TemplateResponse("index.html", context)


@app.get("/tools/abuseipdb", response_class=HTMLResponse)
async def abuseipdb_page(request: Request):
    context = build_common_context(request)
    context.update({"submitted_text": "", "payload": None, "error": None})
    return templates.TemplateResponse("abuseipdb.html", context)


@app.post("/tools/abuseipdb", response_class=HTMLResponse)
async def abuseipdb_submit(request: Request):
    form = await request.form()
    submitted_text = (form.get("ips") or "").strip()
    context = build_common_context(request)
    try:
        payload = await check_ips(submitted_text.splitlines(), settings.abuseipdb_api_key)
        context.update({"submitted_text": submitted_text, "payload": payload, "error": None})
    except AbuseIPDBError as exc:
        context.update({"submitted_text": submitted_text, "payload": None, "error": str(exc)})
    return templates.TemplateResponse("abuseipdb.html", context)


@app.get("/tools/investigation", response_class=HTMLResponse)
async def investigation_page(request: Request):
    context = build_common_context(request)
    context.update({"target": "", "result": None, "error": None})
    return templates.TemplateResponse("investigation.html", context)


@app.post("/tools/investigation", response_class=HTMLResponse)
async def investigation_submit(request: Request):
    form = await request.form()
    target = (form.get("target") or "").strip()
    context = build_common_context(request)
    try:
        result = await investigate_target(target, settings)
        context.update({"target": target, "result": result, "error": None})
    except InvestigationError as exc:
        context.update({"target": target, "result": None, "error": str(exc)})
    return templates.TemplateResponse("investigation.html", context)


@app.get("/healthz")
async def healthz():
    return JSONResponse({"status": "ok"})


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return RedirectResponse(url="/static/favicon.svg")
