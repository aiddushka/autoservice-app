from fastapi import APIRouter, Depends
from app.auth import require_admin

router = APIRouter(prefix="/admin")

@router.get("/stats")
def admin_stats(user=Depends(require_admin)):
    return {"message": "Admin zone", "user": user}
