import os
import argparse
import pyfiglet
import requests
import re
from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from huggingface_hub import HfApi, ModelCard
from duckduckgo_search import DDGS

# --- CLI Setup & Banner ---
def show_banner():
    banner = pyfiglet.figlet_format("AI Evaluator Pro")
    print(banner)
    print("================================================================")
    print(" Made By Aryan Giri | giriaryan694-a11y")
    print(" AI Security Assessment & Discovery")
    print("================================================================\n")

parser = argparse.ArgumentParser(description="AI Model Security Evaluator Web Panel")
server_group = parser.add_argument_group('Server Configuration')
server_group.add_argument("--only-me", action="store_true", help="Bind to 127.0.0.1 so only your computer can access it")
server_group.add_argument("--ip", type=str, help="Comma-separated list of allowed IPs")
server_group.add_argument("--port", type=int, default=5000, help="Port to run the web panel on (default: 5000)")
args = parser.parse_args()

# --- Configuration Loading ---
def load_auth():
    auth_data = {}
    if os.path.exists("auth.txt"):
        with open("auth.txt", "r") as f:
            for line in f:
                if ":" in line:
                    u, p = line.strip().split(":", 1)
                    auth_data[u] = p
    return auth_data

def load_apikeys():
    keys = {"openai": None, "gemini": None, "nvidia": None}
    if os.path.exists("api.txt"):
        with open("api.txt", "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                if "=" in line:
                    key_name, key_val = line.split("=", 1)
                    key_name, key_val = key_name.strip(), key_val.strip().strip('"').strip("'")
                    if "openai_api" in key_name: keys["openai"] = key_val
                    elif "gemini_api-key" in key_name: keys["gemini"] = key_val
                    elif "nvidia_build_api-key" in key_name: keys["nvidia"] = key_val
    return keys

def load_hf_token():
    if os.path.exists("hf_token.txt"):
        with open("hf_token.txt", "r") as f:
            token = f.read().strip()
            if token: return token
    return None

AUTH_DB = load_auth()
API_KEYS = load_apikeys()
HF_TOKEN_FILE = load_hf_token()
ACTIVE_PROVIDERS = {k: v for k, v in API_KEYS.items() if v is not None and v != "<open ai key>"}

if not AUTH_DB:
    print("[!] Warning: auth.txt not found. Defaulting to admin:password")
    AUTH_DB = {"admin": "password"}

# --- Flask Setup ---
app = Flask(__name__)
app.secret_key = os.urandom(24)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

ALLOWED_IPS = args.ip.split(',') if args.ip else []

@app.before_request
def restrict_ips():
    if args.only_me and request.remote_addr != "127.0.0.1":
        return "Access Denied: Tool locked to localhost", 403
    if ALLOWED_IPS and request.remote_addr not in ALLOWED_IPS and request.remote_addr != "127.0.0.1":
        return f"Access Denied: IP {request.remote_addr} not allowed", 403

# --- Core Evaluation Logic (Refactored for Reusability) ---
def perform_security_audit(repo_id, token, provider, eval_model, notes_qty):
    api = HfApi(token=token if token else None)
    
    try:
        try:
            card = ModelCard.load(repo_id, token=token)
            card_text = card.text[:2000]
        except Exception as e:
            card_text = f"Could not load model card: {e}"
        
        try:
            files = api.list_repo_files(repo_id, token=token)
            unsafe_files = [f for f in files if f.endswith(('.pkl', '.pickle', '.pt', '.bin'))]
            safe_files = [f for f in files if f.endswith('.safetensors')]
            
            file_status = f"SafeTensors found: {len(safe_files)}\n"
            if unsafe_files:
                file_status += f"[WARNING] Found {len(unsafe_files)} potentially unsafe serialized files.\n"
            else:
                file_status += "[OK] No unsafe serialized formats detected.\n"
        except Exception as e:
            file_status = f"Failed to list repo files: {e}"
        
        org_name = repo_id.split('/')[0] if '/' in repo_id else repo_id
        ddg_results = ""
        try:
            results = DDGS().text(f"{org_name} AI organization trust security vulnerabilities", max_results=3)
            for r in results:
                ddg_results += f"- {r['title']}: {r['body']}\n"
        except Exception as e:
            ddg_results = f"Search failed: {e}"

        try:
            discussions = api.get_repo_discussions(repo_id, token=token)
            notes = []
            for i, d in enumerate(discussions):
                if notes_qty != 0 and i >= notes_qty: break
                notes.append(f"Title: {d.title} (Status: {d.status})")
            notes_str = "\n".join(notes) if notes else "No community notes found."
        except Exception as e:
             notes_str = f"Failed to fetch community notes: {e}"
        
        prompt = f"""
        You are an AI Security Analyst. Provide a concise, highly structured security evaluation of the Hugging Face model repository: {repo_id}.
        
        Format your response strictly using Markdown. Use Headings (###), Bullet points, bold text, and create a "Consolidated Threat Matrix" Table at the end.
        
        **Context Data:**
        Files Check: {file_status}
        Model Card Info (Excerpt): {card_text}
        DuckDuckGo Org OSINT: {ddg_results}
        Community Notes: {notes_str}
        
        Assess:
        1. Organization Trustworthiness
        2. File Security (Weights format risk)
        3. Potential risks from model card or community.
        """

        report = ""
        key = API_KEYS.get(provider)
        
        if provider == "openai":
            import openai
            client = openai.OpenAI(api_key=key)
            resp = client.chat.completions.create(model=eval_model, messages=[{"role": "user", "content": prompt}])
            report = resp.choices[0].message.content

        elif provider == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=key)
            model = genai.GenerativeModel(eval_model)
            resp = model.generate_content(prompt)
            report = resp.text
            
        elif provider == "nvidia":
            import openai
            client = openai.OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=key)
            resp = client.chat.completions.create(model=eval_model, messages=[{"role": "user", "content": prompt}], max_tokens=2048)
            report = resp.choices[0].message.content

        return report

    except Exception as e:
        return f"### Analysis Error\nAn error occurred during evaluation of {repo_id}:\n```\n{str(e)}\n```"

def discover_best_model(use_case, provider, eval_model):
    prompt = f"Given this use case: '{use_case}', suggest the single best, most popular open-source Hugging Face model repository ID. Reply with ONLY the exact repository ID (e.g., 'mistralai/Mistral-7B-Instruct-v0.2'). Do not include any other text, quotes, or markdown formatting."
    
    key = API_KEYS.get(provider)
    repo_id = ""
    
    if provider == "openai":
        import openai
        client = openai.OpenAI(api_key=key)
        resp = client.chat.completions.create(model=eval_model, messages=[{"role": "user", "content": prompt}])
        repo_id = resp.choices[0].message.content
    elif provider == "gemini":
        import google.generativeai as genai
        genai.configure(api_key=key)
        model = genai.GenerativeModel(eval_model)
        resp = model.generate_content(prompt)
        repo_id = resp.text
    elif provider == "nvidia":
        import openai
        client = openai.OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=key)
        resp = client.chat.completions.create(model=eval_model, messages=[{"role": "user", "content": prompt}])
        repo_id = resp.choices[0].message.content
        
    # Clean up any stray markdown or spaces
    return re.sub(r'[^a-zA-Z0-9_\-\./]', '', repo_id.strip())

# --- UI Templates ---
BASE_CSS = """
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    :root {
        --bg-color: #09090b;
        --surface: #18181b;
        --surface-border: #27272a;
        --primary: #3b82f6;
        --primary-hover: #2563eb;
        --text-main: #f4f4f5;
        --text-muted: #a1a1aa;
        --danger: #ef4444;
        --radius: 12px;
        --transition: all 0.2s ease;
    }
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', sans-serif; background: var(--bg-color); color: var(--text-main); line-height: 1.6; }
    
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-color); }
    ::-webkit-scrollbar-thumb { background: var(--surface-border); border-radius: 4px; }
    
    input, select, textarea { 
        width: 100%; padding: 12px 16px; margin-top: 6px; 
        background: #000000; border: 1px solid var(--surface-border); 
        color: var(--text-main); border-radius: 8px; font-size: 0.95rem; font-family: 'Inter', sans-serif;
    }
    input:focus, select:focus, textarea:focus { border-color: var(--primary); outline: none; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
    
    button { 
        background: var(--primary); color: #ffffff; padding: 12px 24px; 
        border: none; border-radius: 8px; cursor: pointer; font-weight: 600; width: 100%;
        transition: var(--transition); 
    }
    button:hover { background: var(--primary-hover); }
    button:disabled { background: var(--surface-border); color: var(--text-muted); cursor: not-allowed; }
    button.secondary { background: var(--surface); border: 1px solid var(--surface-border); color: var(--text-main); }
    button.secondary:hover { background: #27272a; }

    /* Tabs UI */
    .tabs { display: flex; background: #000; padding: 6px; border-radius: 10px; border: 1px solid var(--surface-border); margin-bottom: 24px; }
    .tab { flex: 1; text-align: center; padding: 10px; cursor: pointer; border-radius: 6px; font-weight: 600; color: var(--text-muted); font-size: 0.9rem; transition: var(--transition); }
    .tab.active { background: var(--surface); color: var(--primary); box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.3s ease; }

    .dashboard { display: grid; grid-template-columns: 380px 1fr; gap: 24px; max-width: 1400px; margin: 0 auto; padding: 24px; min-height: 100vh;}
    .panel { background: var(--surface); padding: 24px; border-radius: var(--radius); border: 1px solid var(--surface-border); }
    .aside-sticky { align-self: start; position: sticky; top: 24px; }
    
    /* Mobile Responsiveness */
    @media (max-width: 900px) { 
        .dashboard { grid-template-columns: 1fr; padding: 12px; gap: 16px; }
        .aside-sticky { position: static; }
        .panel { padding: 16px; }
    }
    
    .form-group { margin-bottom: 20px; text-align: left; }
    label { display: block; font-size: 0.8rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;}
    .flex-row { display: flex; align-items: flex-end; gap: 12px; }
    .flex-row > div { flex: 1; }

    .loader-container { display: none; text-align: center; padding: 40px 0; }
    .spinner { width: 40px; height: 40px; border: 3px solid rgba(59, 130, 246, 0.3); border-radius: 50%; border-top-color: var(--primary); animation: spin 1s ease-in-out infinite; margin: 0 auto 15px auto; }
    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

    /* Markdown Styling */
    #results { display: none; font-size: 0.95rem; color: #e4e4e7; overflow-x: auto;}
    #results h1, #results h2, #results h3 { color: #ffffff; margin: 1.5em 0 0.75em 0; }
    #results h1:first-child, #results h2:first-child { margin-top: 0; }
    #results ul, #results ol { padding-left: 20px; margin-bottom: 1.2em; }
    #results code { background: rgba(255,255,255,0.1); padding: 0.2em 0.4em; border-radius: 4px; font-family: monospace; }
    #results pre { background: #000; padding: 16px; border-radius: 8px; overflow-x: auto; border: 1px solid var(--surface-border); margin-bottom: 1.2em;}
    #results table { width: 100%; border-collapse: collapse; margin-bottom: 1.5em; background: #000; border-radius: 8px; overflow: auto; display: block;}
    #results th, #results td { padding: 12px; border: 1px solid var(--surface-border); min-width: 120px;}
    #results th { background: rgba(255,255,255,0.05); color: var(--primary); }
</style>
"""

LOGIN_HTML = BASE_CSS + """
<!DOCTYPE html><html><head><title>Login - AI Evaluator Pro</title></head>
<body style="display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px;">
    <div style="background: var(--surface); padding: 3rem 2rem; border-radius: var(--radius); border: 1px solid var(--surface-border); width: 100%; max-width: 400px; text-align: center;">
        <h1 style="color: var(--primary); margin-bottom: 5px; font-size: 1.8rem;">AI Evaluator Pro</h1>
        <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 30px;">Made By Aryan Giri | giriaryan694-a11y</p>
        <form method="POST">
            <div class="form-group"><input type="text" name="username" placeholder="Username" required></div>
            <div class="form-group" style="margin-bottom: 25px;"><input type="password" name="password" placeholder="Password" required></div>
            <button type="submit">Login</button>
        </form>
        {% if error %}<p style="color: var(--danger); margin-top: 15px;">{{ error }}</p>{% endif %}
    </div>
</body></html>
"""

APP_HTML = BASE_CSS + """
<!DOCTYPE html><html><head><title>AI Security Evaluator Pro</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script>
    let allModels = [];
    marked.setOptions({ gfm: true, breaks: true });

    function switchTab(tabId) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.querySelector(`[onclick="switchTab('${tabId}')"]`).classList.add('active');
        document.getElementById(tabId).classList.add('active');
    }

    async function fetchModels() {
        const provider = document.getElementById('provider').value;
        const select = document.getElementById('eval_model');
        const btn = document.getElementById('fetch_btn');
        btn.textContent = "Fetching..."; btn.disabled = true;
        select.innerHTML = '<option>Loading models...</option>';
        try {
            const res = await fetch(`/api/models?provider=${provider}`);
            allModels = await res.json();
            filterModels();
        } catch (e) {
            select.innerHTML = '<option value="">Error</option>';
        } finally {
            btn.textContent = "Fetch"; btn.disabled = false;
        }
    }

    function filterModels() {
        const query = document.getElementById('model_search').value.toLowerCase();
        const select = document.getElementById('eval_model');
        select.innerHTML = '';
        const filtered = allModels.filter(m => m.toLowerCase().includes(query));
        if (filtered.length === 0) { select.innerHTML = '<option>No models found</option>'; return; }
        filtered.forEach(m => {
            const opt = document.createElement('option'); opt.value = m; opt.textContent = m;
            select.appendChild(opt);
        });
    }

    function prepareUIForRun(loaderText) {
        document.getElementById('loader').style.display = 'block';
        document.getElementById('loader-text').innerText = loaderText;
        document.getElementById('results').style.display = 'none';
        document.getElementById('placeholder-state').style.display = 'none';
    }

    async function runDirectAudit(e) {
        e.preventDefault();
        const evalModel = document.getElementById('eval_model').value;
        if (!evalModel || evalModel.includes('Loading')) return alert("Select an evaluation model.");
        
        prepareUIForRun("Analyzing repository topology and compiling threat report...");
        
        const data = {
            repo: document.getElementById('repo').value,
            provider: document.getElementById('provider').value,
            eval_model: evalModel,
            notes_qty: document.getElementById('notes_qty').value
        };

        try {
            const res = await fetch('/evaluate', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
            document.getElementById('results').innerHTML = marked.parse(await res.text());
        } catch(err) {
            document.getElementById('results').innerHTML = `<p style='color: var(--danger);'>Error: ${err.message}</p>`;
        } finally {
            document.getElementById('loader').style.display = 'none';
            document.getElementById('results').style.display = 'block';
        }
    }

    async function runDiscovery(e) {
        e.preventDefault();
        const evalModel = document.getElementById('eval_model').value;
        if (!evalModel || evalModel.includes('Loading')) return alert("Select an evaluation model.");
        
        prepareUIForRun("Searching Hugging Face for the best model match...");
        
        const data = {
            use_case: document.getElementById('use_case').value,
            provider: document.getElementById('provider').value,
            eval_model: evalModel,
            notes_qty: document.getElementById('notes_qty').value
        };

        try {
            const res = await fetch('/find_and_evaluate', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
            document.getElementById('results').innerHTML = marked.parse(await res.text());
        } catch(err) {
            document.getElementById('results').innerHTML = `<p style='color: var(--danger);'>Error: ${err.message}</p>`;
        } finally {
            document.getElementById('loader').style.display = 'none';
            document.getElementById('results').style.display = 'block';
        }
    }
</script>
</head><body onload="fetchModels()">
    <div class="dashboard">
        
        <aside class="panel aside-sticky">
            <div style="margin-bottom: 20px;">
                <h1 style="color: var(--primary); font-size: 1.4rem; font-weight: 700;">AI Evaluator Pro</h1>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">Made By Aryan Giri | giriaryan694-a11y</div>
            </div>

            <div style="background: #000; padding: 15px; border-radius: 8px; border: 1px solid var(--surface-border); margin-bottom: 20px;">
                <div class="flex-row form-group" style="margin-bottom: 10px;">
                    <div>
                        <label>LLM Engine</label>
                        <select id="provider" onchange="fetchModels()">
                            {% for p in providers %} <option value="{{ p }}">{{ p | capitalize }}</option> {% endfor %}
                        </select>
                    </div>
                    <button type="button" class="secondary" id="fetch_btn" onclick="fetchModels()" style="width: auto;">Sync</button>
                </div>
                <div class="form-group" style="margin-bottom: 0;">
                    <label>Eval Model</label>
                    <input type="text" id="model_search" placeholder="Search (e.g. gpt-4)" onkeyup="filterModels()" style="margin-bottom: 6px;">
                    <select id="eval_model" required></select>
                </div>
            </div>

            <div class="tabs">
                <div class="tab active" onclick="switchTab('tab-audit')">Direct Audit</div>
                <div class="tab" onclick="switchTab('tab-discover')">Find Model</div>
            </div>

            <div id="tab-audit" class="tab-content active">
                <form onsubmit="runDirectAudit(event)">
                    <div class="form-group">
                        <label>Hugging Face Repo</label>
                        <input type="text" id="repo" placeholder="deepseek-ai/DeepSeek-V4-Pro" required>
                    </div>
                    <div class="form-group">
                        <label>Community Notes Analysis Qty</label>
                        <input type="number" id="notes_qty" value="5" min="0">
                    </div>
                    <button type="submit" style="margin-top: 10px;">Run Security Audit</button>
                </form>
            </div>

            <div id="tab-discover" class="tab-content">
                <form onsubmit="runDiscovery(event)">
                    <div class="form-group">
                        <label>Describe Your Use Case</label>
                        <textarea id="use_case" rows="3" placeholder="e.g. I need a lightweight model for offline English to French translation..." required></textarea>
                    </div>
                    <button type="submit" style="margin-top: 10px;">Find & Audit Model</button>
                </form>
            </div>
            
        </aside>

        <main class="panel" style="min-height: 80vh;">
            <div id="loader" class="loader-container">
                <div class="spinner"></div>
                <div id="loader-text" class="loader-text" style="color: var(--text-muted); margin-top: 15px;">Initializing...</div>
            </div>
            
            <div id="placeholder-state" style="text-align: center; color: var(--surface-border); padding-top: 20vh;">
                <h3 style="color: var(--text-muted); margin-bottom: 8px;">Awaiting Target Parameters</h3>
                <p style="font-size: 0.9rem; color: #52525b;">Configure the audit on the left to generate a report.</p>
            </div>

            <div id="results"></div>
        </main>
    </div>
</body></html>
"""

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    error = None
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        if user in AUTH_DB and AUTH_DB[user] == pwd:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = "Invalid Authentication Credentials"
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/')
def index():
    if not session.get('logged_in'): return redirect(url_for('login'))
    if not ACTIVE_PROVIDERS: return "Error: No valid API keys found in api.txt."
    return render_template_string(APP_HTML, providers=list(ACTIVE_PROVIDERS.keys()))

@app.route('/api/models')
def api_models():
    if not session.get('logged_in'): return jsonify([])
    provider = request.args.get('provider')
    key = API_KEYS.get(provider)
    fetched_models = []

    try:
        if provider == "openai":
            import openai
            client = openai.OpenAI(api_key=key)
            fetched_models = [m.id for m in client.models.list().data if "gpt" in m.id or "o1" in m.id]
        elif provider == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=key)
            fetched_models = [m.name.replace('models/', '') for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
        elif provider == "nvidia":
            import openai
            client = openai.OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=key)
            fetched_models = [m.id for m in client.models.list().data]
    except Exception:
        fallbacks = {
            "openai": ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
            "gemini": ["gemini-1.5-pro", "gemini-1.5-flash"],
            "nvidia": ["meta/llama3-70b-instruct", "mistralai/mixtral-8x22b-instruct-v0.1"]
        }
        fetched_models = fallbacks.get(provider, [])

    return jsonify(sorted(fetched_models))

@app.route('/evaluate', methods=['POST'])
def evaluate():
    if not session.get('logged_in'): return "Unauthorized", 401
    data = request.json
    return perform_security_audit(
        repo_id=data.get('repo'), 
        token=HF_TOKEN_FILE, 
        provider=data.get('provider'), 
        eval_model=data.get('eval_model'), 
        notes_qty=int(data.get('notes_qty', 5))
    )

@app.route('/find_and_evaluate', methods=['POST'])
def find_and_evaluate():
    if not session.get('logged_in'): return "Unauthorized", 401
    data = request.json
    
    use_case = data.get('use_case')
    provider = data.get('provider')
    eval_model = data.get('eval_model')
    notes_qty = int(data.get('notes_qty', 5))
    
    # 1. Discover the Model
    try:
        best_repo = discover_best_model(use_case, provider, eval_model)
        if not best_repo or " " in best_repo:
            return "### Error\nFailed to confidently identify a single Hugging Face repository for this use case."
    except Exception as e:
        return f"### Discovery Error\nCould not process use case: {e}"

    # 2. Audit the Discovered Model
    report = perform_security_audit(best_repo, HF_TOKEN_FILE, provider, eval_model, notes_qty)
    
    # Append the discovery context to the top of the report
    final_output = f"## 🎯 Discovery Result\n**Suggested Repository:** `{best_repo}`\n\n---\n\n" + report
    return final_output

# --- Main Execution ---
if __name__ == "__main__":
    show_banner()
    host = "127.0.0.1" if args.only_me else "0.0.0.0"
    print(f"[*] Core Online. Binding to port {args.port}...")
    if HF_TOKEN_FILE: print("[*] HF Authorization: Secure token loaded.")
    app.run(host=host, port=args.port, debug=False)
