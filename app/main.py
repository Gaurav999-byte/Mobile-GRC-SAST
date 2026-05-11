import os
import time
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .analyzer import analyze_apk
from .riskmapper import map_findings, severity_summary
from .reporter import render_and_save_report

BASE_DIR = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(os.path.dirname(BASE_DIR), "uploads")
REPORT_DIR = os.path.join(os.path.dirname(BASE_DIR), "outputs", "reports")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

app = FastAPI(title="GRC-SAST Tool")

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
app.mount("/reports", StaticFiles(directory=REPORT_DIR), name="reports")

templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


# =========================
# HOME PAGE
# =========================
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    empty_summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "summary": empty_summary
        }
    )


# =========================
# SCAN APK
# =========================
@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, file: UploadFile = File(...)):

    try:
        ts = int(time.time())
        safe_name = f"{ts}_{file.filename}"
        file_path = os.path.join(UPLOAD_DIR, safe_name)

        # save file
        contents = await file.read()

        with open(file_path, "wb") as f:
            f.write(contents)

        print(f"[main] Saved upload: {file_path}")
        print(f"[main] File size: {os.path.getsize(file_path)} bytes")

        # analyze apk
        findings = analyze_apk(file_path)
        print(f"[main] Analyzer returned {len(findings)} findings")

        # map findings
        mapped = map_findings(findings)
        print(f"[main] Mapped findings count: {len(mapped)}")

        # summary
        summary = severity_summary(mapped)

        # generate reports
        paths = render_and_save_report(mapped, safe_name, REPORT_DIR)

        print("[main] REPORT PATHS:", paths)

        # safe file extraction
        html_file = paths.get("html")
        html_file = os.path.basename(html_file) if html_file else None

        pdf_file = paths.get("pdf")
        pdf_file = os.path.basename(pdf_file) if pdf_file else None

        docx_file = paths.get("docx")
        docx_file = os.path.basename(docx_file) if docx_file else None

        chart_file = paths.get("chart")
        chart_file = os.path.basename(chart_file) if chart_file else None

        # render dashboard
        return templates.TemplateResponse(
            request,
            "report_preview.html",
            {
                "app_name": file.filename,
                "findings": mapped,
                "report_file": html_file,
                "pdf_file": pdf_file,
                "docx_file": docx_file,
                "chart_file": chart_file,
                "summary": summary
            }
        )

    except Exception as e:
        print("[main] ERROR during scan:", repr(e))

        return HTMLResponse(
            f"<h3>Error: {str(e)}</h3><p>Check server logs.</p>",
            status_code=500
        )