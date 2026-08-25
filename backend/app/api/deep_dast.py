from fastapi import APIRouter, HTTPException
from app.commercial.deep_dast import DeepAuthenticatedDAST, DeepDASTRequest, RetestRequest

router = APIRouter(prefix="/api/commercial/deep-dast", tags=["Commercial Deep Authenticated DAST"])
engine = DeepAuthenticatedDAST()

@router.post("/scan")
async def deep_scan(request: DeepDASTRequest):
    try:
        return (await engine.scan(request)).model_dump()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.post("/retest")
async def retest(request: RetestRequest):
    try:
        return await engine.retest(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
