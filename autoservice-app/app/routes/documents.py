from fastapi import APIRouter
from app.models import Document

router = APIRouter(prefix="/documents")

@router.post("/")
def create_document(doc: Document):
    return {"created": doc}
