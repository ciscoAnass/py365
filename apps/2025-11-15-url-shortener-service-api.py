import os
import random
import string
import time
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from redis import Redis

app = FastAPI()

# Connect to Redis
redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = os.getenv("REDIS_PORT", 6379)
redis_password = os.getenv("REDIS_PASSWORD", None)
redis_client = Redis(host=redis_host, port=redis_port, password=redis_password)

# Define the length of the short code
SHORT_CODE_LENGTH = 6

def generate_short_code() -> str:
    """
    Generate a unique, collision-resistant short code.
    """
    characters = string.ascii_letters + string.digits
    short_code = ''.join(random.choices(characters, k=SHORT_CODE_LENGTH))
    
    # Check if the short code already exists in Redis
    while redis_client.get(short_code) is not None:
        short_code = ''.join(random.choices(characters, k=SHORT_CODE_LENGTH))
    
    return short_code

def create_short_url(long_url: str) -> str:
    """
    Create a short URL and store it in Redis.
    """
    short_code = generate_short_code()
    redis_client.set(short_code, long_url)
    return short_code

def get_long_url(short_code: str) -> Optional[str]:
    """
    Retrieve the long URL from Redis using the short code.
    """
    long_url = redis_client.get(short_code)
    if long_url is None:
        return None
    return long_url.decode("utf-8")

def increment_click_count(short_code: str):
    """
    Increment the click count for the given short code in Redis.
    """
    redis_client.incr(f"{short_code}:clicks")

def get_click_count(short_code: str) -> int:
    """
    Retrieve the click count for the given short code from Redis.
    """
    click_count = redis_client.get(f"{short_code}:clicks")
    if click_count is None:
        return 0
    return int(click_count)

@app.post("/shorten")
def shorten_url(request: Request, url: str):
    """
    Create a short URL for the given long URL.
    """
    short_code = create_short_url(url)
    short_url = f"{request.base_url.rstrip('/')}/{short_code}"
    return {"short_url": short_url}

@app.get("/{short_code}")
def redirect_to_long_url(short_code: str):
    """
    Redirect the user to the long URL associated with the given short code.
    """
    long_url = get_long_url(short_code)
    if long_url is None:
        raise HTTPException(status_code=404, detail="Short code not found")
    
    increment_click_count(short_code)
    return RedirectResponse(url=long_url)

@app.get("/analytics/{short_code}")
def get_click_analytics(short_code: str):
    """
    Retrieve the click count for the given short code.
    """
    click_count = get_click_count(short_code)
    return {"short_code": short_code, "click_count": click_count}