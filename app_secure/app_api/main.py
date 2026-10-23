import requests
import jwt 
import datetime
from fastapi import FastAPI, HTTPException, Header
import secrets 
import socket
import ipaddress
from urllib.parse import urlparse, urlunparse

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

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addr_info= socket.getaddrinfo(hostname, port, proto= socket.IPPROTO_TCP)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Hostname Resolution Failed")

    if not addr_info:
        raise HTTPException(status_code=404, detail="No DNS Records Found")

    validated_ips= []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str=sockaddr[0]
        try:
            ip_obj= ipaddress.ip_address(ip_str)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid IP address")
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            raise HTTPException(status_code=403, detail="Access to internal or private network is denied")
        validated_ips.append(ip_str)

    last_error= None
    for ip in validated_ips:
        pinned_netloc = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        pinned_url_parts = parsed._replace(netloc=pinned_netloc)
        pinned_url= urlunparse(pinned_url_parts)
        req_headers = {"Host": hostname}
        try:
            response= requests.get(pinned_url, headers= req_headers, allow_redirects=False)
            break
        except requests.exceptions.RequestException as e:
            last_error=e
    if response is None:
        raise HTTPException(status_code=502, detail="Failed to fetch data")
        

    return {"status":"import", "content_preview":response.text[:100]}

    # try:
    #     ip_addr= socket.gethostbyname(hostname)
    #     ip_obj= ipaddress.ip_address(ip_addr)
    #     if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
    #         raise HTTPException(status_code=403, detail="Access to internal or private network is denied")
    # except socket.gaierror:
    #     raise HTTPException(status_code=400, detail="Hostname resolution failed")

    response= requests.get(target_url)
    return {"status":"import", "content_preview":response.text[:100]}


# Mitigate app-specific vulnerability allowing data access across users
@app.post("/datasets/{dataset_id}/export")
def trigger_export(dataset_id: str, payload: dict, auth: str= Header(...)):
    user = decode_token(auth)
    output_filename = payload.get("output_filename", f"export_{dataset_id}.md")

    # check if the requested data belongs to the user or not
    headers= {"Auth": auth}
    verify_res = requests.get(f"http://127.0.0.1:8001/records/{dataset_id}", headers=headers)
    if verify_res.status_code != 200:
        raise HTTPException(status_code= verify_res.status_code, detail=verify_res.text)

    task_payload={
        "sub":"processing_service",
        "job_for": user['sub'],
        "allowed_dataset": dataset_id,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
    }
    task_token= jwt.encode(task_payload, header, algorithm="HS256")

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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

