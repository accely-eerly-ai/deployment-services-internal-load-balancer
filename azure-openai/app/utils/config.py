
from fastapi import FastAPI, HTTPException, Security, status, Depends
from fastapi.openapi.models import APIKey
from fastapi.security import APIKeyHeader

import os

API_KEY = os.getenv('API_KEY', None)

if not API_KEY:
    raise ValueError("API_KEY environment variable is not set")

# Set up API key security dependency
api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=True)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == API_KEY:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate X-API-KEY"
    )

# Usage

app = FastAPI()

@app.get("/api_key_demo")
async def process_document(api_key: APIKey = Depends(get_api_key)):
    return {"message": "Hello World"}