from fastapi import FastAPI, Header, HTTPException
import jwt

app= FastAPI(title= "Resource Service")
header= "secret_jwt_key"

# hardcoding datasets
datasets = {
    "ds_alice_1": {
        "owner":"alice",
        "title":"Alice Private Genomic Samples",
        "records":[
            {"id": "rec_1", "title": "Sample 01", "value": "Sensitive Biomarker A"},
            {"id":"rec_2","title":"Sample 02", "value": "Sensitive Biomarker B"}
        ]
    },
    "ds_bob_1": {
        "owner":"bob",
        "title":"Bob Financial Transactions",
        "records":[
            {"id": "rec_1", "title": "FY 2024", "value": "EUR 45,000"},
            {"id": "rec_2", "title": "FY 2025", "value": "EUR 45,000"}
        ]
    }
}

exports_db= {}

def decode_token(auth: str):
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token bearer")
    token= auth.split(" ")[1]
    try:
        token= jwt.decode(token, header, algorithms=['HS256'])
        return token
    except Exception:
        raise HTTPException(status_code= 401, detail='Invalid Token')

# Mitigate CWE-862 
@app.get("/records/{dataset_id}")
def get_records(dataset_id: str, auth: str = Header(...)):
    token_data = decode_token(auth)
    
    if dataset_id not in datasets:
        raise HTTPException(status_code=404, detail="Dataset not found")
        
    dataset = datasets[dataset_id]
    
    # Case A: Request from Processing Service carrying a Task Token
    if token_data.get("sub") == "processing_service":
        if token_data.get("allowed_dataset") != dataset_id:
            raise HTTPException(
                status_code=403, 
                detail=f"Forbidden: Task token not authorized for dataset {dataset_id}"
            )
        return dataset
        
    # Case B: Direct User Request — Enforce Complete Mediation
    requester = token_data.get("sub")
    role = token_data.get("role")
    
    if role != "admin" and dataset["owner"] != requester:
        raise HTTPException(
            status_code=403, 
            detail="Forbidden: You do not have permission to access this resource"
        )
        
    return dataset

# @app.get("/records/{dataset_id}")
# def get_records(dataset_id: str, auth:str= Header(None), service_token: str= Header(None) ):
#     user= get_auth(auth, service_token) # bypasses any authentication/authorization checks
#     if dataset_id not in datasets:
#         raise HTTPException(status_code=401, detail='No records found')

#     # no check on the user['sub'] which can tell user name
#     # even though the earlier bypass would render it useless
#     return datasets[dataset_id]

@app.post("/exports/save")
def save_export(payload:dict, auth: str= Header(...)):
    token_data= decode_token(auth)
    if token_data.get("sub")!= "processing_service":
        raise HTTPException(status_code=403, detail="Forbidden: Only processing workers can save export")

    export_id= payload.get('export_id')
    exports_db[export_id]= payload
    return {"status":"saved", "export_id":export_id}

@app.get('/exports/{export_id}')
def get_export(export_id: str):
    
    if export_id not in exports_db:
        raise HTTPException(status_code=404, detail='Export not found')
    return exports_db[export_id]

@app.get("/internal/status")
def internal_status():
    return {"service": "resource_service", "status": "operational", "internal_network": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)