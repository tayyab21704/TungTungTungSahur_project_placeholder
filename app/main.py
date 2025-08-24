from fastapi import FastAPI
from app.routes import auth, workflow_routes

app = FastAPI(
    title="AWS Agentic AI",
)

# Include routers
app.include_router(auth.router)
app.include_router(workflow_routes.router)