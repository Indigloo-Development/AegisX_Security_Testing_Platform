import uuid
from fastapi import APIRouter, HTTPException
from app.commercial.browser import BrowserScanner, BrowserScanRequest, ScanQueue

router = APIRouter(prefix="/api/commercial/browser", tags=["Commercial Browser Scanner"])
scanner = BrowserScanner()
queue = ScanQueue()

@router.post("/scan")
async def start_scan(request: BrowserScanRequest):
    job_id = uuid.uuid4().hex
    try:
        job = queue.submit(job_id, scanner.scan(request))
        return {"job_id": job.id, "status": job.status, "target_url": str(request.target_url)}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

@router.get("/scan/{job_id}")
def scan_status(job_id: str):
    job = queue.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    result = job.result.model_dump() if job.result and hasattr(job.result, "model_dump") else job.result
    return {"job_id": job.id, "status": job.status, "error": job.error, "result": result}

@router.post("/scan/{job_id}/cancel")
def cancel_scan(job_id: str):
    if not queue.get(job_id):
        raise HTTPException(status_code=404, detail="Scan job not found")
    ok = queue.cancel(job_id)
    return {"job_id": job_id, "cancelled": ok}
