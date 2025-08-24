from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth

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