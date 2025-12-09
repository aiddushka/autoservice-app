from fastapi import Depends, HTTPException

def get_current_user():
    # Заглушка — позже можно прикрутить JWT или куки
    return {"id": 1, "username": "admin", "role": "admin"}

def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user
