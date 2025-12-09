from fastapi import FastAPI
from app.routes import main, admin, documents

app = FastAPI(title="Autoservice API")

app.include_router(main.router)
app.include_router(admin.router)
app.include_router(documents.router)
