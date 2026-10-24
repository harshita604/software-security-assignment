import streamlit as st
import requests
import os

API_URL = "http://127.0.0.1:8000"
RESOURCE_URL = "http://127.0.0.1:8001"
PROCESSING_URL = "http://127.0.0.1:8002"

st.set_page_config(page_title="Research Workspace Dashboard", layout="wide")

st.title(" Research Workspace — Vulnerability  Console")
st.caption("Investigating authorization boundaries, composition flaws, and mitigation controls across microservices.")

# Sidebar: User Authentication & Mode Selection
st.sidebar.header("Authentication & Profile")
username = st.sidebar.selectbox("Select User Identity", ["alice", "bob", "admin"])
password= "alice123" if username=="alice" else "bob123" if username =="bob" else "admin123" 


if "token" not in st.session_state or st.session_state.get("current_user") != username:
    try:
        res = requests.post(f"{API_URL}/auth/login", json={"username": username, "password": password})
        if res.status_code == 200:
            st.session_state["token"] = res.json()["access_token"]
            st.session_state["current_user"] = username
            st.sidebar.success(f"Logged in as {username}")
        else:
            st.sidebar.error("Failed to authenticate with Application API")
    except Exception as e:
        st.sidebar.error(f"Cannot reach Application API (:8000): {e}")



# Tabs for the 4 core security test scenarios
tab1, tab2, tab3, tab4 = st.tabs([
    "1. CWE-862 (Missing Authorization)",
    "2. Composition Flaw (Confused Deputy)",
    "3. CWE-918 (SSRF)",
    "4. CWE-22 (Path Traversal)"
])

headers = {"Auth": f"Bearer {st.session_state.get('token', '')}"}

#  TAB 1: CWE-862 
with tab1:
    st.subheader("CWE-862: Missing Object-Level Authorization")
    st.write("Demonstrates reading datasets directly from the Resource Service without ownership checks.")
    
    target_dataset = st.selectbox("Target Dataset ID", ["ds_alice_1", "ds_bob_1"], key="t1_target")
    
    if st.button("Fetch Dataset Record", key="btn_cwe_862"):
        res = requests.get(f"{RESOURCE_URL}/records/{target_dataset}", headers=headers)
        if res.status_code == 200:
            st.success(f"HTTP 200 OK — Data retrieved successfully!")
            st.json(res.json())
            if target_dataset == "ds_bob_1" and username == "alice":
                st.warning("Access Violation: Alice accessed Bob's private records without authorization!")
            if target_dataset == "ds_alice_1" and username == "bob" :
                st.warning("Access Violation: Bob accessed Alice's private records without authorization !")
        elif res.status_code == 403:
            st.info(" HTTP 403 Forbidden — Complete Mediation enforced! Access denied.")
            st.json(res.json())
        else:
            st.error(f"HTTP {res.status_code}: {res.text}")

#  TAB 2: Composition Flaw (Confused Deputy) 
with tab2:
    st.subheader("Composition Vulnerability: Confused Deputy via Over-Privileged Service Interconnect")
    st.write("Demonstrates an ordinary user leveraging the Processing Service to extract records owned by another tenant.")
    
    st.info("Flow: User (Alice) ➔ Application API (:8000) ➔ Processing Service (:8002) ➔ Resource Service (:8001)")
    
    comp_dataset = st.selectbox("Target Dataset to Export", ["ds_bob_1", "ds_alice_1"], key="t4_ds")
    
    if st.button("Execute Multi-Tier Export", key="btn_comp"):
        job_payload = {
            "output_filename": f"export_{comp_dataset}.md"
        }
        res = requests.post(f"{API_URL}/datasets/{comp_dataset}/export", json=job_payload, headers=headers)
        if res.status_code == 200:
            export_info = res.json()
            st.success(f"Export Job Completed: Export ID = {export_info.get('export_id')}")
            
            # Fetch generated export artifact
            exp_res = requests.get(f"{RESOURCE_URL}/exports/{export_info.get('export_id')}")
            if exp_res.status_code == 200:
                st.markdown("### Exported Artifact Content:")
                st.markdown(exp_res.json().get("content", ""))
                if comp_dataset == "ds_bob_1" and username == "alice":
                    st.warning(" Confused Deputy Exploit Succeeded: Alice exported Bob's records through service delegation!")
                if comp_dataset == "ds_alice_1" and username == "bob" :
                    st.warning("Access Violation: Bob accessed Alice's private records without authorization")
        elif res.status_code == 403:
            st.info(" HTTP 403 Forbidden: Delegated task token rejected unauthorized tenant access!")
            st.json(res.json())
        else:
            st.error(f"HTTP {res.status_code}: {res.text}")


#  TAB 3: CWE-918 (SSRF) 
with tab3:
    st.subheader("CWE-918: Server-Side Request Forgery")
    st.write("Induces the Application API to act as a proxy into unexposed or loopback endpoints.")
    
    target_url = st.text_input("Remote Resource URL", value=f"{RESOURCE_URL}/internal/status")
    
    if st.button("Request Remote Import", key="btn_cwe_918"):
        res = requests.post(f"{API_URL}/datasets/import-remote", json={"url": target_url}, headers=headers)
        if res.status_code == 200:
            st.success("HTTP 200 OK — Remote response fetched:")
            st.code(res.json().get("content_preview", ""))
            if "resource_service" in res.json().get("content_preview", ""):
                st.warning(" SSRF Succeeded: Edge API queried internal service at 127.0.0.1:8001!")
        elif res.status_code == 400 or res.status_code == 403:
            st.info(f" HTTP {res.status_code} Blocked: Private IP / Loopback filter prevented SSRF.")
            st.json(res.json())
        else:
            st.error(f"HTTP {res.status_code}: {res.text}")

#  TAB 4: CWE-22 (Path Traversal) 
with tab4:
    st.subheader("CWE-22: Path Traversal in Export Worker")
    st.write("Demonstrates arbitrary file write beyond the designated export directory.")
    
    col1, col2 = st.columns(2)
    with col1:
        export_dataset = st.selectbox("Source Dataset", ["ds_alice_1", "ds_bob_1"], key="t2_ds")
    with col2:
        custom_filename = st.text_input("Export Filename", value="../arbitrary_overwrite.txt")

    
    if st.button("Trigger Processing Job", key="btn_cwe_22"):
        payload ={
            "output_filename": custom_filename
        }
        res = requests.post(f"{API_URL}/datasets/{export_dataset}/export", json=payload, headers=headers)
        # payload = {
        #     "dataset_id": export_dataset,
        #     "output_filename": custom_filename
        #     # "task_token": "dummy_token"  
        # }
        # res = requests.post(f"{PROCESSING_URL}/job/export", json=payload)
        # if res.json().get("detail")=="Missing required parameters or task token":
        #     payload = {
        #         "dataset_id": export_dataset,
        #         "output_filename": custom_filename,
        #         "task_token": "dummy_token" # since this is just for testing if path validation works, a dummy token is used
        #     }

        if res.status_code == 200:
            export_info = res.json()
            st.success(f"Export Job Completed: Export ID = {export_info.get('export_id')}")
            if os.path.exists("./arbitrary_overwrite.txt"):
                st.warning("Traversal Succeeded: File escaped ./workspace_exports and wrote to project root!")
        elif res.status_code == 403:
            st.info(f"HTTP {res.status_code} Blocked: You cannot access this data")
            st.json(res.json())
        elif res.status_code == 400:
            st.info(f"HTTP {res.status_code} Blocked: Path validation prevented path traversal.")
            st.json(res.json())
        else:
            st.error(f"HTTP {res.status_code}: {res.text}")