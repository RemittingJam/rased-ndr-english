from pathlib import Path
import shutil
import tempfile

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.services.analyzer import analyze_pcap
from app.services.demo import build_demo_result

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="Rased NDR",
    version="0.1.1",
    description="Explainable PCAP analysis and network detection platform.",
)

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "Rased NDR", "version": "0.1.1"}


@app.post("/api/demo")
def demo() -> dict:
    return build_demo_result()


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)) -> dict:
    filename = file.filename or "capture.pcap"
    suffix = Path(filename).suffix.lower()

    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(
            status_code=400,
            detail="Supported formats: .pcap, .pcapng, .cap",
        )

    temp_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            shutil.copyfileobj(file.file, temp_file)
            temp_path = Path(temp_file.name)

        if temp_path.stat().st_size > 100 * 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail="Maximum upload size is 100 MB.",
            )

        return analyze_pcap(temp_path, original_name=filename)

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Could not analyze the capture: {exc}",
        ) from exc
    finally:
        await file.close()
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)
