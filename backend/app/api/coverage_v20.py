from fastapi import APIRouter
from app.testlab.coverage import build_coverage_matrix
router = APIRouter(prefix='/api/coverage-v20', tags=['coverage-v20'])
@router.get('/matrix')
def coverage_matrix():
    return build_coverage_matrix()
