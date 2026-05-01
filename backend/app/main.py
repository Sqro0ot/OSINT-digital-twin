from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db import Base, engine
from app.api import router
from app.scheduler import start_scheduler

Base.metadata.create_all(bind=engine)

app = FastAPI(title="OSINT Digital Twin Prototype")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # локальная сеть — все origins разрешены
    allow_credentials=False,  # False обязателен при allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.on_event("startup")
def on_startup():
    start_scheduler()
