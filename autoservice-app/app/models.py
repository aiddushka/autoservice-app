from pydantic import BaseModel


class User(BaseModel):
    id: int | None = None
    username: str
    role: str | None = None


class Document(BaseModel):
    id: int | None = None
    title: str
    content: str
    owner_id: int | None = None
