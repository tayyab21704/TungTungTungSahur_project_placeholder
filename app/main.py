from fastapi import FastAPI
from app.routes import auth

app = FastAPI(
    title="AWS Agentic AI",
)

# Include routers
app.include_router(auth.router)