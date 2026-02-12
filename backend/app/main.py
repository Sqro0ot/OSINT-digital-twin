from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db import Base, engine
from app.api import router
from app.scheduler import start_scheduler

Base.metadata.create_all(bind=engine)

app = FastAPI(title="OSINT Digital Twin Prototype")

# Добавь CORS middleware ДО подключения роутеров
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Разрешить фронтенд
    allow_credentials=True,
    allow_methods=["*"],  # Разрешить все HTTP методы
    allow_headers=["*"],  # Разрешить все заголовки
)

app.include_router(router)

@app.on_event("startup")
def on_startup():
    start_scheduler()
