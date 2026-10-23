import os
import uuid
import requests
from fastapi import FastAPI, HTTPException
from dataset_formatter import format_summary

app= FastAPI(title='Processing Service')
base_dir= os.path.dirname(os.path.abspath(__file__))
new_dir= os.path.abspath(os.path.join(base_dir, "../../workspace_exports")) #path to save exports
os.makedirs(new_dir, exist_ok= True)

@app.post("/job/export")
def run_export(job:dict): #input from application API
    dataset_id= job.get('dataset_id')
    task_token= job.get('task_token')
    output_filename= job.get("output_filename")

    if not dataset_id or task_token or output_filename:
        raise HTTPException(status_code=400, detail="Missing required parameters or task token")
        
    #  Mitigate CWE-22 Path traversal vulnerability
    clean_filename= os.path.basename(output_filename)
    if clean_filename!= output_filename or ".." in output_filename:
        raise HTTPException(status_code=400, detail="Path traversal sequences detected in filename")

    file_path= os.path.abspath(os.path.join(new_dir, clean_filename))
    if not file_path.startswith(new_dir):
        raise HTTPException(status_code=400, detail="Illegal output path location")

        # update headers from a token that bypasses everything to specific task token to manage access
    headers={"Auth":f"Bearer {task_token}"}
    res= requests.get(f'http://127.0.0.1:8001/records/{dataset_id}', headers= headers )
    if res.status_code != 200:
        raise HTTPException(status_code= res.status_code, detail='Failed to fetch records from DB')
    records= res.json().get("records",[])
    format_content= format_summary(records)
    
    with open(file_path, "w") as f:
        f.write(format_content)

    export_id= str(uuid.uuid4())
    save_payload={
        "export_id":export_id,
        "dataset_id": dataset_id,
        "path":file_path,
        "content":format_content
    }
    requests.post("http://127.0.0.1:8001/exports/save", json=save_payload, headers=headers)

    return {
        "status":"completed",
        "export_id": export_id,
        "written_path":file_path
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)



