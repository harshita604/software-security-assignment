# Multi-Tenant Secure Research Workspace

A distributed research workspace featuring strict tenant boundary isolation, role-based access control, and automated SSDLC security gates.

## Application Purpose
Enables scientific researchers to securely manage and export research datasets while restricting cross-tenant data access and providing administrators with privileged audit visibility.

## Seeded User Credentials
* `alice` / `password123` (Role: `user`)
* `bob` / `password123` (Role: `user`)
* `admin` / `adminpassword` (Role: `admin`)

---

## Quickstart: Build, Run, and Test

### 1. Prerequisites & Environment Setup
Ensure Python 3.10+ is installed. Clone the repository and initialize the virtual environment:

```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install bandit pip_audit pytest requests uvicorn streamlit

# Build and install the required external helper package
cd packages\dataset_formatter
pip install .\packages\dataset_formatter

# The services folder contains the files with planted vulnerabilities
# The app_secure folder contains the files after mitigating vulnerabilities

# Terminal 1: Resource Service (Port 8001)
uvicorn app_secure.resource_service.main:app --host 127.0.0.1 --port 8001

# Terminal 2: Processing Service (Port 8002)
uvicorn app_secure.processing_service.main:app --host 127.0.0.1 --port 8002

# Terminal 3: Application API (Port 8000)
uvicorn app_secure.app_api.main:app --host 127.0.0.1 --port 8000

# Visualise how the mitigations work using streamlit
# The same UI file can be used to see how the vulnerabilities work, by running the insecure files # on the previous terminals as:
# uvicorn services.resource_service.main:app --host 127.0.0.1 --port 8001
# uvicorn services.processing_service.main:app --host 127.0.0.1 --port 8002
# uvicorn services.app_api.main:app --host 127.0.0.1 --port 8000
streamlit run ui.py

# Run the 6 automated functional and authorization security gates
pytest tests/test_security.py 

# Run Static Analysis (SAST)
bandit -r services/ -lll

# Run Software Composition Analysis (SCA)
pip_audit -r requirements.txt