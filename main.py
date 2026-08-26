from fastapi import FastAPI, Query, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyHeader, APIKeyQuery
from starlette.exceptions import HTTPException as StarletteHTTPException
from pymongo import MongoClient
import duckdb
import os
import secrets
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load Environment Variables
load_dotenv()
MONGO_URI = os.getenv("MONGODB_URI")
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "admin123")

# Initialize MongoDB
mongo_client = MongoClient(MONGO_URI)
db = mongo_client["hitek_gateway"]
keys_collection = db["api_keys"]
logs_collection = db["api_logs"]

# Initialize FastAPI & DuckDB
app = FastAPI(docs_url=None, redoc_url=None) # Docs disabled for security
con = duckdb.connect()
con.execute("INSTALL httpfs;")
con.execute("LOAD httpfs;")

# Security Dependancies
security = HTTPBasic()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)

def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != ADMIN_USER or credentials.password != ADMIN_PASS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def verify_api_key(request: Request, key_header: str = Depends(api_key_header), key_query: str = Depends(api_key_query)):
    api_key = key_header or key_query
    if not api_key:
        raise HTTPException(status_code=403, detail="API Key is missing")
    
    key_data = keys_collection.find_one({"api_key": api_key})
    if not key_data:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    
    if not key_data.get("is_active"):
        raise HTTPException(status_code=403, detail="API Key has been revoked")
        
    if datetime.utcnow() > key_data.get("expires_at"):
        keys_collection.update_one({"api_key": api_key}, {"$set": {"is_active": False}})
        raise HTTPException(status_code=403, detail="API Key has expired")
    
    # Log the request
    logs_collection.insert_one({
        "client_name": key_data["client_name"],
        "api_key_snippet": api_key[:6] + "...",
        "endpoint": request.url.path,
        "ip_address": request.client.host,
        "timestamp": datetime.utcnow()
    })
    
    return api_key

# ----------------- HTML TEMPLATES -----------------

LANDING_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hitek Data Gateway - LIVE</title>
    <style>
        body { margin: 0; overflow: hidden; background-color: #050505; color: #00ffcc; font-family: 'Courier New', Courier, monospace; }
        #canvas-container { position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; }
        .overlay { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; background: rgba(10, 10, 10, 0.85); padding: 50px; border: 1px solid #00ffcc; border-radius: 12px; box-shadow: 0 0 30px rgba(0, 255, 204, 0.3); backdrop-filter: blur(5px); }
        h1 { margin: 0 0 15px 0; font-size: 3.5em; text-transform: uppercase; letter-spacing: 6px; text-shadow: 0 0 15px #00ffcc; }
        p { font-size: 1.2em; margin: 8px 0; color: #ccc; }
        .highlight { color: #00ffcc; font-weight: bold; }
        .status-box { margin-top: 30px; font-weight: bold; padding: 15px; border-radius: 8px; background: rgba(0, 255, 204, 0.1); border: 1px solid rgba(0, 255, 204, 0.5); font-size: 1.1em; }
        .blinking { animation: blinker 1.5s linear infinite; display: inline-block; }
        @keyframes blinker { 50% { opacity: 0; } }
    </style>
</head>
<body>
    <div id="canvas-container"></div>
    <div class="overlay">
        <h1>SYSTEM ONLINE</h1>
        <p>API Gateway is <span class="highlight">Active & Secured</span></p>
        <p>Parquet Cloud Engine: <span class="highlight">Connected</span></p>
        <div class="status-box"><span class="blinking" style="color: #00ffcc;">●</span> HTTP 200 OK - LISTENING FOR QUERIES</div>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script>
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 2000);
        const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        document.getElementById('canvas-container').appendChild(renderer.domElement);
        const geometry = new THREE.BufferGeometry();
        const vertices = [];
        for (let i = 0; i < 8000; i++) {
            vertices.push(THREE.MathUtils.randFloatSpread(3000), THREE.MathUtils.randFloatSpread(3000), THREE.MathUtils.randFloatSpread(3000));
        }
        geometry.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
        const material = new THREE.PointsMaterial({ color: 0x00ffcc, size: 2.5, transparent: true, opacity: 0.8 });
        const points = new THREE.Points(geometry, material);
        scene.add(points);
        camera.position.z = 1200;
        function animate() { requestAnimationFrame(animate); points.rotation.x += 0.0005; points.rotation.y += 0.001; renderer.render(scene, camera); }
        animate();
    </script>
</body>
</html>
"""

# ----------------- EXCEPTION HANDLER -----------------
@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        return JSONResponse(
            status_code=404,
            content={
                "status": "rejected",
                "message": "Invalid endpoint. STRICTLY use /FetchData?Number=XXXXXXXXXX",
                "Developer": "@Aswatthama_0x"
            }
        )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "Developer": "@Aswatthama_0x"}
    )

# ----------------- PUBLIC ROUTES -----------------
@app.get("/", response_class=HTMLResponse)
def root_landing_page():
    return HTMLResponse(content=LANDING_PAGE_HTML, status_code=200)

@app.get("/FetchData")
def fetch_data(Number: str = Query(None), api_key: str = Depends(verify_api_key)):
    if not Number or not Number.isdigit() or len(Number) < 10 or len(Number) > 15:
        return JSONResponse(
            status_code=400,
            content={
                "status": "rejected",
                "message": "Invalid parameter. STRICTLY use /FetchData?Number=XXXXXXXXXX",
                "Developer": "@Aswatthama_0x"
            }
        )
    
    last_digit = Number[-1]
    
    # Updated Hugging Face Buckets URLs
    primary_url = f"https://huggingface.co/buckets/CutehackX/hitek-data-bucket/resolve/main/final_master_shard_{last_digit}.parquet"
    alt_url = f"https://huggingface.co/buckets/CutehackX/hitek-data-bucket/resolve/main/alt_master_shard_{last_digit}.parquet"
    
    try:
        query = f"""
            SELECT *, 'Main' AS _record_type FROM read_parquet('{primary_url}') WHERE mobile = '{Number}'
            UNION ALL
            SELECT *, 'Alt' AS _record_type FROM read_parquet('{alt_url}') WHERE alt = '{Number}'
        """
        raw_results = con.execute(query).df().to_dict(orient="records")
        
        main_records = []
        alt_records = []
        
        for row in raw_results:
            rec_type = row.pop('_record_type')
            if rec_type == 'Main':
                main_records.append(row)
            else:
                alt_records.append(row)
        
        if not main_records and not alt_records:
            return JSONResponse(
                status_code=404,
                content={
                    "status": "not_found", 
                    "phone": Number,
                    "Developer": "@Aswatthama_0x"
                }
            )
            
        return {
            "status": "success", 
            "Data": {
                "Main_Records": main_records,
                "Alt_Records": alt_records
            },
            "Developer": "@Aswatthama_0x"
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Database processing error: {str(e)}",
                "Developer": "@Aswatthama_0x"
            }
        )

# ----------------- PRO ADMIN DASHBOARD (HTML + TAILWIND) -----------------
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(admin: str = Depends(verify_admin)):
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Control Panel</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-white p-8">
        <div class="max-w-6xl mx-auto">
            <h1 class="text-3xl font-bold text-teal-400 mb-8 border-b border-teal-400 pb-4">API Key Management Dashboard</h1>
            
            <div class="bg-gray-800 p-6 rounded-lg shadow-lg mb-8 border border-gray-700">
                <h2 class="text-xl font-semibold mb-4 text-teal-300">Issue New API Key</h2>
                <div class="flex gap-4">
                    <input type="text" id="clientName" placeholder="Client Name" class="p-3 bg-gray-900 border border-gray-600 rounded w-1/3 text-white focus:outline-none focus:border-teal-400">
                    <select id="daysValid" class="p-3 bg-gray-900 border border-gray-600 rounded text-white w-1/4 focus:outline-none focus:border-teal-400">
                        <option value="7">7 Days</option>
                        <option value="30" selected>30 Days</option>
                        <option value="90">90 Days</option>
                        <option value="365">1 Year</option>
                    </select>
                    <button onclick="createKey()" class="bg-teal-500 hover:bg-teal-400 text-gray-900 px-6 py-3 rounded font-bold transition-colors">Generate Key</button>
                </div>
                <p id="newKeyDisplay" class="mt-4 text-green-400 font-mono font-bold"></p>
            </div>

            <div class="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700">
                <h2 class="text-xl font-semibold mb-4 text-teal-300">Active API Keys</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left table-auto">
                        <thead>
                            <tr class="text-gray-400 border-b border-gray-600">
                                <th class="pb-3">Client</th>
                                <th class="pb-3">Key (Snippet)</th>
                                <th class="pb-3">Expires At</th>
                                <th class="pb-3">Status</th>
                                <th class="pb-3">Action</th>
                            </tr>
                        </thead>
                        <tbody id="keysTable"></tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <script>
            async function fetchKeys() {
                const res = await fetch('/admin/api/keys');
                const data = await res.json();
                let html = '';
                data.keys.forEach(k => {
                    const statusClass = k.is_active ? 'text-green-400' : 'text-red-400';
                    const statusText = k.is_active ? 'Active' : 'Revoked';
                    const btnClass = k.is_active ? 'bg-red-500 hover:bg-red-400 text-white' : 'bg-green-500 hover:bg-green-400 text-gray-900';
                    const btnText = k.is_active ? 'Revoke Access' : 'Activate Access';
                    
                    html += `
                    <tr class="border-b border-gray-700 hover:bg-gray-700 transition-colors">
                        <td class="py-4 font-semibold">${k.client_name}</td>
                        <td class="font-mono text-gray-300">${k.api_key.substring(0,10)}...</td>
                        <td class="text-gray-300">${new Date(k.expires_at).toLocaleDateString()}</td>
                        <td class="${statusClass} font-bold">${statusText}</td>
                        <td>
                            <button onclick="toggleKey('${k.api_key}')" class="${btnClass} px-4 py-2 rounded text-sm font-bold transition-colors">
                                ${btnText}
                            </button>
                        </td>
                    </tr>`;
                });
                document.getElementById('keysTable').innerHTML = html;
            }
            
            async function createKey() {
                const client = document.getElementById('clientName').value;
                const days = document.getElementById('daysValid').value;
                if(!client) return alert('Please enter a client name.');
                
                const res = await fetch(`/admin/api/keys?client_name=${client}&days=${days}`, {method: 'POST'});
                const data = await res.json();
                
                document.getElementById('newKeyDisplay').innerText = `SUCCESS! Copy this key and send to client: ${data.api_key}`;
                document.getElementById('clientName').value = '';
                fetchKeys();
            }
            
            async function toggleKey(key) {
                if(confirm('Are you sure you want to change the status of this key?')) {
                    await fetch(`/admin/api/keys/toggle?api_key=${key}`, {method: 'POST'});
                    fetchKeys();
                }
            }
            
            fetchKeys();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# ----------------- ADMIN LOGIC API -----------------
@app.post("/admin/api/keys")
def create_api_key(client_name: str, days: int = 30, admin: str = Depends(verify_admin)):
    new_key = "hitek_" + secrets.token_hex(20)
    expires = datetime.utcnow() + timedelta(days=days)
    keys_collection.insert_one({
        "client_name": client_name,
        "api_key": new_key,
        "created_at": datetime.utcnow(),
        "expires_at": expires,
        "is_active": True
    })
    return {"status": "success", "client_name": client_name, "api_key": new_key, "expires_at": expires}

@app.get("/admin/api/keys")
def list_api_keys(admin: str = Depends(verify_admin)):
    keys = list(keys_collection.find({}, {"_id": 0}).sort("created_at", -1))
    return {"keys": keys}

@app.post("/admin/api/keys/toggle")
def toggle_api_key(api_key: str, admin: str = Depends(verify_admin)):
    key_data = keys_collection.find_one({"api_key": api_key})
    if key_data:
        new_status = not key_data["is_active"]
        keys_collection.update_one({"api_key": api_key}, {"$set": {"is_active": new_status}})
        return {"status": "success", "new_status": new_status}
    raise HTTPException(status_code=404, detail="Key not found")
