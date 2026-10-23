import requests
import jwt 
import datetime
from fastapi import FastAPI, HTTPException, Header
import secrets 
import socket
import ipaddress
from urllib.parse import urlparse

app= FastAPI(title= "Application API")
header= "secret_jwt_key"
seeded_users={
    "alice":{"password":"alice123", "role":"user"},
    "bob":{"password":"bob123", "role":"user"},
    "admin":{"password":"admin123","role":"admin"}
}

@app.post("/auth/login")
def login(creds: dict):
    user= seeded_users.get(creds.get("username"))
    if not user or user['password']!= creds.get("password"):
        raise HTTPException(status_code=401, detail='Invalid login credentials')

    payload={
        "sub": creds.get("username"),
        "role": user["role"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
    }
    token= jwt.encode( payload, header, algorithm="HS256")
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

#CWE 918 vulnerability
@app.post("/datasets/import-remote")
def import_remote(payload: dict, auth: str= Header(...)):
    token= decode_token(auth)
    target_url= payload.get('url')
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing URL")

    # vulnerable as server calls the entered url without any checks
    response= requests.get(target_url)
    return {"status":"import", "content_preview":response.text[:100]}

# App-specific vulnerability allowing data access across users
@app.post("/datasets/{dataset_id}/export")
def trigger_export(dataset_id: str, payload: dict, auth: str= Header(...)):
    user = decode_token(auth)
    output_filename = payload.get("output_filename", f"export_{dataset_id}.md")
    
    # The API forwards dataset_id, but the processing service fetches data without token checking
    job_payload = {
        "dataset_id": dataset_id,
        "requested_by": user["sub"],
        "output_filename": output_filename
    }
    
    res = requests.post("http://127.0.0.1:8002/job/export", json=job_payload)
    if res.status_code != 200:
        raise HTTPException(status_code=res.status_code, detail=res.text)
    return res.json()

# Mitigating CWE-918
@app.post("/datasets/import-remote")
def import_remote(payload: dict, auth: str= Header(...)):
    token= decode_token(auth)
    target_url= payload.get('url')
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing URL")

    parsed= urlparse(target_url)
    if parsed.scheme not in ['http', 'https']:
        raise HTTPException(status_code=400, detail= "Invalid protocol")

    hostname= parsed.hostname
    if not hostname:
        raise HTTPException(status_code=404, detail="Invalid URL")
    try:
        ip_addr= socket.gethostbyname(hostname)
        ip_obj= ipaddress.ip_address(ip_addr)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            raise HTTPException(status_code=403, detail="Access to internal or private network is denied")
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Hostname resolution failed")

    response= requests.get(target_url)
    return {"status":"import", "content_preview":response.text[:100]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

