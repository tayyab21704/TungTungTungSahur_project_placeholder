from fastapi import FastAPI
from app.routes import auth, workflow_routes, aws_chat_routes
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="AWS Agentic AI",
)

# List of origins that are allowed to make requests to your API
origins = [
    "*", # This allows all origins
]

# Add CORSMiddleware to the application
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # This allows all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # This allows all headers
)

# Include routers
app.include_router(auth.router)
app.include_router(workflow_routes.router)
app.include_router(aws_chat_routes.router)