from fastapi import APIRouter
from app.utils import hello

router = APIRouter()

@router.get("/")
def root():
    return {"message": "API работает", "utils": hello()}
