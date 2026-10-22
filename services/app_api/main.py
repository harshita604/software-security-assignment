import requests
import jwt 
import datetime
from fastapi import FastAPI, HTTPException
import secrets 
app= FastAPI("Application API")

header= secrets.token_hex()
seeded_users={
    "alice":{"password":"alice123", "role":"user"},
    "bob":{"password":"bob123", "role":"user"},
    "admin":{"password":"admin123","role":"admin"}
}

@app.post("/auth/login")
def login(creds: dict):
    user= seeded_users.get(creds.get("username"))
    if not user or user['password']!= creds.get("password"):
        raise HTTPException(status_code='401', detail='Invalid login credentials')

    payload={
        "user": creds.get("username"),
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    token= jwt.encode(header, payload, algorithm="HS256")
    return {"access_token":token, "token_type":"bearer"}

def decode_token(auth: str):
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token bearer")
    token= auth.split(" ")[1]
    try:
        token= jwt.decode(token, header, algorithms=['HS256'])
        return token
    except Exception:
        raise HTTPException(status_code= 401, detail='Invalid Token')

