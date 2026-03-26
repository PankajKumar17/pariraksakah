import os
import requests
from fastapi import Request, HTTPException
from typing import Callable

TRUST_REGISTRY_URL = os.getenv("DNA_TRUST_REGISTRY_URL", "http://dna-trust-registry:8053")

async def verify_dna_middleware(request: Request, call_next: Callable):
    caller_dna = request.headers.get("X-Caller-DNA-ID")
    service_name = os.getenv("SERVICE_NAME", "python-service")
    
    if not caller_dna:
        raise HTTPException(status_code=401, detail="Missing DNA Identity / Trust Verification")
        
    # Check Trust Registry
    try:
        r = requests.get(f"{TRUST_REGISTRY_URL}/trust/verify/{caller_dna}/{service_name}", timeout=2)
        if r.status_code != 200:
            raise HTTPException(status_code=403, detail="DNA Trust Score Verification Failed")
    except requests.RequestException:
        raise HTTPException(status_code=503, detail="Trust Registry Unavailable")
        
    response = await call_next(request)
    response.headers["X-Component-DNA"] = f"{service_name}-DNA-Hash"
    return response

# Usage in FastAPI:
# app.middleware("http")(verify_dna_middleware)
