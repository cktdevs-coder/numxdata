from fastapi import FastAPI, Query, Request, Depends, HTTPException, status, Cookie, Form, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import APIKeyHeader, APIKeyQuery
from starlette.exceptions import HTTPException as StarletteHTTPException
from pymongo import MongoClient
import duckdb
import os
import secrets
import hashlib
import math
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load Environment Variables
load_dotenv()
MONGO_URI = os.getenv("MONGODB_URI")
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "admin123")

# Security Token Hash
ADMIN_HASH = hashlib.sha256(f"{ADMIN_USER}:{ADMIN_PASS}".encode()).hexdigest()

# Set Your Hidden Admin Path
SECRET_ADMIN_PATH = "/nxd-secret-panel"

# Initialize MongoDB
try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = mongo_client["hitek_gateway"]
    keys_collection = db["api_keys"]
    logs_collection = db["api_logs"]
except Exception as e:
    print(f"MongoDB Connection Error: {e}")

# Initialize FastAPI & DuckDB
app = FastAPI(docs_url=None, redoc_url=None) 
con = duckdb.connect()
con.execute("INSTALL httpfs;")
con.execute("LOAD httpfs;")

# Security Dependencies
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)

# Helper function to clean NaN values for JSON compliance
def clean_nan(obj):
    if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
        return None
    elif isinstance(obj, dict):
        return {k: clean_nan(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_nan(v) for v in obj]
    return obj

# Cookie Based Admin Auth
def verify_admin(admin_auth: str = Cookie(None)):
    if not admin_auth or admin_auth != ADMIN_HASH:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

# API Key Validation
def verify_api_key(request: Request, key_header: str = Depends(api_key_header), key_query: str = Depends(api_key_query)):
    api_key = key_header or key_query
    if not api_key:
        raise HTTPException(status_code=401, detail="API is missing")
    
    key_data = keys_collection.find_one({"api_key": api_key})
    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    if not key_data.get("is_active"):
        raise HTTPException(status_code=401, detail="API Key has been revoked")
        
    if datetime.utcnow() > key_data.get("expires_at"):
        keys_collection.update_one({"api_key": api_key}, {"$set": {"is_active": False}})
        raise HTTPException(status_code=401, detail="API Key has expired")
    
    # Track Usage & Logs
    keys_collection.update_one({"api_key": api_key}, {"$inc": {"usage_count": 1}})
    logs_collection.insert_one({
        "client_name": key_data["client_name"],
        "api_key": api_key,
        "endpoint": request.url.path,
        "ip_address": request.client.host,
        "timestamp": datetime.utcnow()
    })
    
    return api_key

# ----------------- EXCEPTION HANDLERS -----------------
@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code in [401, 403]:
        return JSONResponse(
            status_code=exc.status_code, 
            content={
                "status": "error",
                "message": "API Key is missing or invalid.",
                "Developer": "@Aswatthama_0x",
                "Buy_API": "Contact on Telegram: https://t.me/Aswatthama_0x"
            }
        )
    return JSONResponse(
        status_code=exc.status_code, 
        content={"status": "rejected", "message": exc.detail, "Developer": "@Aswatthama_0x"}
    )

# ----------------- PUBLIC ROUTES (NO HTML) -----------------
@app.get("/", response_class=JSONResponse)
def root_landing_page():
    return {
        "status": "Api is running",
        "message": "numXdata api is running",
        "Developer": "@Aswatthama_0x",
        "Buy_API": "Contact on Telegram: https://t.me/Aswatthama_0x"
    }

@app.get("/FetchData")
def fetch_data(Number: str = Query(None), api_key: str = Depends(verify_api_key)):
    if not Number or not Number.isdigit() or len(Number) < 10 or len(Number) > 15:
        return JSONResponse(status_code=400, content={"status": "rejected", "message": "Invalid parameter.", "Developer": "@Aswatthama_0x"})
    
    last_digit = Number[-1]
    
    primary_url = f"https://huggingface.co/buckets/CutehackX/hitek-data-bucket/resolve/final_master_shard_{last_digit}.parquet?download=true"
    alt_url = f"https://huggingface.co/buckets/CutehackX/hitek-data-bucket/resolve/alt_master_shard_{last_digit}.parquet?download=true"
    
    try:
        # Optimized query to fetch ALL matching records without limits, utilizing httpfs caching for speed
        query = f"""
            SELECT *, 'Main' AS _record_type FROM read_parquet('{primary_url}') WHERE mobile = '{Number}'
            UNION ALL
            SELECT *, 'Alt' AS _record_type FROM read_parquet('{alt_url}') WHERE alt = '{Number}'
        """
        raw_results = con.execute(query).df().to_dict(orient="records")
        
        # Clean NaN values
        cleaned_results = clean_nan(raw_results)
        
        # Group all matching rows into respective lists
        main_records = [row for row in cleaned_results if row.pop('_record_type') == 'Main']
        alt_records = [row for row in cleaned_results if row.pop('_record_type', None) == 'Alt']
        
        if not main_records and not alt_records:
            return JSONResponse(status_code=404, content={"status": "not_found", "phone": Number, "Developer": "@Aswatthama_0x"})
            
        return {
            "status": "success", 
            "Total_Main_Results": len(main_records),
            "Total_Alt_Results": len(alt_records),
            "Data": {
                "Main_Records": main_records,
                "Alt_Records": alt_records
            },
            "Developer": "@Aswatthama_0x"
        }
    
    except Exception as e:
        print(f"DUCKDB CRASH LOG: {str(e)}")
        return JSONResponse(status_code=500, content={"status": "error", "message": f"Data process error: {str(e)}", "Developer": "@Aswatthama_0x"})

# ----------------- SECURE FORM LOGIN SYSTEM -----------------
LOGIN_HTML = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>NXD Security Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 h-screen flex items-center justify-center">
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl border border-teal-500 w-96">
        <h2 class="text-2xl font-bold text-teal-400 mb-6 text-center">NXD Admin Access</h2>
        <form action="{SECRET_ADMIN_PATH}/login" method="POST" class="flex flex-col gap-4">
            <input type="text" name="username" placeholder="Username" class="p-3 bg-gray-900 text-white rounded border border-gray-600 focus:border-teal-400 focus:outline-none" required>
            <input type="password" name="password" placeholder="Password" class="p-3 bg-gray-900 text-white rounded border border-gray-600 focus:border-teal-400 focus:outline-none" required>
            <button type="submit" class="bg-teal-500 hover:bg-teal-400 text-gray-900 font-bold py-3 rounded mt-2">Login to Dashboard</button>
        </form>
    </div>
</body>
</html>
"""

@app.get(SECRET_ADMIN_PATH, response_class=HTMLResponse)
def admin_dashboard(request: Request, admin_auth: str = Cookie(None)):
    if not admin_auth or admin_auth != ADMIN_HASH:
        return HTMLResponse(content=LOGIN_HTML)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NXD Admin Console</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-white p-8 font-sans">
        <div class="max-w-7xl mx-auto">
            <div class="flex justify-between items-center border-b border-teal-500 pb-4 mb-8">
                <h1 class="text-3xl font-bold text-teal-400">NXD Security Dashboard</h1>
                <div class="flex gap-4 items-center">
                    <span class="bg-teal-900 text-teal-300 px-3 py-1 rounded-full text-sm">Dev: @Aswatthama_0x</span>
                    <a href="{SECRET_ADMIN_PATH}/logout" class="bg-red-600 hover:bg-red-500 px-4 py-2 rounded font-bold text-sm transition-colors">Logout</a>
                </div>
            </div>
            
            <div class="bg-gray-800 p-6 rounded-lg shadow-lg mb-8 border border-gray-700">
                <h2 class="text-xl font-semibold mb-4 text-teal-300">Issue API Key</h2>
                <div class="flex flex-wrap gap-4 items-center">
                    <input type="text" id="clientName" placeholder="Client Name*" class="p-3 bg-gray-900 border border-gray-600 rounded w-1/4 text-white focus:outline-none focus:border-teal-400">
                    <input type="text" id="customKey" placeholder="Custom API (Optional)" class="p-3 bg-gray-900 border border-gray-600 rounded w-1/4 text-white focus:outline-none focus:border-teal-400">
                    <select id="daysValid" class="p-3 bg-gray-900 border border-gray-600 rounded text-white w-32 focus:outline-none focus:border-teal-400">
                        <option value="7">7 Days</option><option value="30" selected>30 Days</option><option value="365">1 Year</option>
                    </select>
                    <button onclick="createKey()" class="bg-teal-500 hover:bg-teal-400 text-gray-900 px-6 py-3 rounded font-bold transition-colors">Generate NXD Key</button>
                </div>
                <p id="newKeyDisplay" class="mt-4 text-green-400 font-mono font-bold"></p>
            </div>

            <div class="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700">
                <div class="overflow-x-auto">
                    <table class="w-full text-left table-auto">
                        <thead>
                            <tr class="text-gray-400 border-b border-gray-600 text-sm uppercase">
                                <th class="pb-3">Client</th><th class="pb-3">API Key</th><th class="pb-3">Usage</th>
                                <th class="pb-3">Expires At</th><th class="pb-3">Status</th><th class="pb-3 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="keysTable"></tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <script>
            const adminPath = "{SECRET_ADMIN_PATH}";
            
            async function fetchKeys() {{
                const res = await fetch(adminPath + '/api/keys');
                if(res.status === 401) window.location.reload();
                const data = await res.json();
                
                let html = '';
                data.keys.forEach(k => {{
                    const statusClass = k.is_active ? 'text-green-400' : 'text-yellow-400';
                    const statusText = k.is_active ? 'Active' : 'Disabled';
                    html += `
                    <tr class="border-b border-gray-700 hover:bg-gray-700 transition-colors">
                        <td class="py-4 font-semibold">${{k.client_name}}</td>
                        <td class="font-mono text-teal-200">${{k.api_key}}</td>
                        <td class="font-bold text-purple-400">${{k.usage_count || 0}} Hits</td>
                        <td class="text-gray-300">${{new Date(k.expires_at).toLocaleDateString()}}</td>
                        <td class="${{statusClass}} font-bold">${{statusText}}</td>
                        <td class="text-right space-x-2">
                            <button onclick="toggleKey('${{k.api_key}}')" class="bg-gray-600 hover:bg-gray-500 px-3 py-1 rounded text-xs text-white">Toggle</button>
                            <button onclick="extendKey('${{k.api_key}}')" class="bg-blue-600 hover:bg-blue-500 px-3 py-1 rounded text-xs text-white">+30 Days</button>
                            <button onclick="deleteKey('${{k.api_key}}')" class="bg-red-600 hover:bg-red-500 px-3 py-1 rounded text-xs text-white">Delete</button>
                        </td>
                    </tr>`;
                }});
                document.getElementById('keysTable').innerHTML = html;
            }}
            
            async function createKey() {{
                const client = document.getElementById('clientName').value;
                const custom = document.getElementById('customKey').value;
                const days = document.getElementById('daysValid').value;
                if(!client) return alert('Enter Client Name');
                
                const res = await fetch(`${{adminPath}}/api/keys?client_name=${{client}}&days=${{days}}&custom_key=${{custom}}`, {{method: 'POST'}});
                const data = await res.json();
                document.getElementById('newKeyDisplay').innerText = `SUCCESS! Key: ${{data.api_key}}`;
                fetchKeys();
            }}
            
            async function toggleKey(key) {{ await fetch(`${{adminPath}}/api/keys/toggle?api_key=${{key}}`, {{method: 'POST'}}); fetchKeys(); }}
            async function extendKey(key) {{ if(confirm('Extend 30 days?')) {{ await fetch(`${{adminPath}}/api/keys/extend?api_key=${{key}}&days=30`, {{method: 'POST'}}); fetchKeys(); }} }}
            async function deleteKey(key) {{ if(confirm('Delete permanently?')) {{ await fetch(`${{adminPath}}/api/keys/delete?api_key=${{key}}`, {{method: 'DELETE'}}); fetchKeys(); }} }}
            
            fetchKeys();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post(SECRET_ADMIN_PATH + "/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        response = RedirectResponse(url=SECRET_ADMIN_PATH, status_code=303)
        response.set_cookie(key="admin_auth", value=ADMIN_HASH, httponly=True, max_age=86400)
        return response
    
    return HTMLResponse(content="<script>alert('Invalid Credentials!'); window.location.href='" + SECRET_ADMIN_PATH + "';</script>")

@app.get(SECRET_ADMIN_PATH + "/logout")
def logout():
    response = RedirectResponse(url=SECRET_ADMIN_PATH, status_code=303)
    response.delete_cookie("admin_auth")
    return response

# ----------------- ADMIN API MANAGEMENT LOGIC -----------------
@app.post(f"{SECRET_ADMIN_PATH}/api/keys")
def create_api_key(client_name: str, days: int = 30, custom_key: str = None, is_admin: bool = Depends(verify_admin)):
    new_key = custom_key.strip() if custom_key else "NXD_" + secrets.token_hex(4)
    if keys_collection.find_one({"api_key": new_key}): raise HTTPException(status_code=400, detail="Custom Key already exists!")
    keys_collection.insert_one({"client_name": client_name, "api_key": new_key, "created_at": datetime.utcnow(), "expires_at": datetime.utcnow() + timedelta(days=days), "is_active": True, "usage_count": 0})
    return {"status": "success", "api_key": new_key}

@app.get(f"{SECRET_ADMIN_PATH}/api/keys")
def list_api_keys(is_admin: bool = Depends(verify_admin)):
    keys = list(keys_collection.find({}, {"_id": 0}).sort("created_at", -1))
    return {"keys": keys}

@app.post(f"{SECRET_ADMIN_PATH}/api/keys/toggle")
def toggle_api_key(api_key: str, is_admin: bool = Depends(verify_admin)):
    key_data = keys_collection.find_one({"api_key": api_key})
    if key_data: keys_collection.update_one({"api_key": api_key}, {"$set": {"is_active": not key_data["is_active"]}})
    return {"status": "success"}

@app.post(f"{SECRET_ADMIN_PATH}/api/keys/extend")
def extend_api_key(api_key: str, days: int = 30, is_admin: bool = Depends(verify_admin)):
    key_data = keys_collection.find_one({"api_key": api_key})
    if key_data: keys_collection.update_one({"api_key": api_key}, {"$set": {"expires_at": key_data["expires_at"] + timedelta(days=days)}})
    return {"status": "success"}

@app.delete(f"{SECRET_ADMIN_PATH}/api/keys/delete")
def delete_api_key(api_key: str, is_admin: bool = Depends(verify_admin)):
    if keys_collection.delete_one({"api_key": api_key}).deleted_count > 0:
        logs_collection.delete_many({"api_key": api_key})
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Key not found")
