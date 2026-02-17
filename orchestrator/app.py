from dotenv import load_dotenv
load_dotenv()

import os
import tempfile
import shutil
from multiprocessing import Pool
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
import requests
from git import Repo
import json

# ==========
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/favicon.ico")
def favicon():
    return ("", 204)

@app.get("/__debug_paths")
def __debug_paths():
    index_path = os.path.join(STATIC_DIR, "index.html")
    
    if os.path.exists(index_path):
        file_size = os.path.getsize(index_path)
    else:
        file_size = None
    
    if os.path.isdir(STATIC_DIR):
        files = os.listdir(STATIC_DIR)
    else:
        files = None
    
    return jsonify({
        "BASE_DIR": BASE_DIR,
        "STATIC_DIR": STATIC_DIR,
        "index_path": index_path,
        "index_exists": os.path.exists(index_path),
        "index_size_bytes": file_size,
        "static_files": files
    })

@app.get("/")
def home():
    print("SERVING INDEX FROM:", os.path.join(STATIC_DIR, "index.html"))
    return send_from_directory(STATIC_DIR, "index.html")
# ==========



SCANNER_URL = os.getenv('SCANNER_URL', 'http://scanner:8001')
MAX_WORKERS = 10  

def is_scannable_file(file_path: Path) -> bool:
    """Check if a file should be scanned."""
    # Skip hidden files and directories (like .git)
    return not any(part.startswith('.') for part in file_path.parts)


def scan_file(args: tuple) -> dict:
    """Send a file to the scanner service."""
    file_path, scanner_url = args
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        response = requests.post(
            f'{scanner_url}/scan',
            json={
                'filename': str(file_path),
                'content': content
            },
            timeout=30
        )

        if response.status_code == 200:
            return response.json()
        else:
            return {
                'filename': str(file_path),
                'error': f'Scanner returned status {response.status_code}'
            }
    except Exception as e:
        return {
            'filename': str(file_path),
            'error': str(e)
        }

def scan_local_path(local_path: str, scanner_url: str) -> dict:
    """Scan a local directory for secrets."""
    repo_path = Path(local_path)

    if not repo_path.exists():
        raise ValueError(f"Path does not exist: {local_path}")

    if not repo_path.is_dir():
        raise ValueError(f"Path is not a directory: {local_path}")

    # Find all scannable files
    files_to_scan = [
        f for f in repo_path.rglob('*')
        if f.is_file() and is_scannable_file(f.relative_to(repo_path))
    ]

    print(f"Found {len(files_to_scan)} files to scan")

    # Scan files in parallel using multiprocessing
    scan_args = [(file_path, scanner_url) for file_path in files_to_scan]
    with Pool(processes=MAX_WORKERS) as pool:
        results = pool.map(scan_file, scan_args)

    # Aggregate results
    files_with_secrets = [r for r in results if r.get('has_secrets', False)]
    files_with_errors = sum(1 for r in results if 'error' in r)
    files_scanned = len(results) - files_with_errors

    return {
        'path': local_path,
        'summary': {
            'total_files_scanned': files_scanned,
            'files_with_secrets': len(files_with_secrets),
            'files_with_errors': files_with_errors
        },
        'findings': files_with_secrets,
        'all_results': results
    }

def clone_and_scan_repo(repo_url: str, scanner_url: str) -> dict:
    """Clone a repository and scan all files."""
    temp_dir = tempfile.mkdtemp()

    try:
        # Clone the repository
        print(f"Cloning repository: {repo_url}")
        repo = Repo.clone_from(repo_url, temp_dir, depth=1)

        # Use the local scan function
        result = scan_local_path(temp_dir, scanner_url)
        result['repo_url'] = repo_url
        result.pop('path', None)
        return result

    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    # Check if scanner is reachable
    try:
        response = requests.get(f'{SCANNER_URL}/health', timeout=5)
        scanner_healthy = response.status_code == 200
    except:
        scanner_healthy = False

    return jsonify({
        "status": "healthy" if scanner_healthy else "degraded",
        "scanner_status": "healthy" if scanner_healthy else "unhealthy"
    }), 200




@app.route('/scan-repo', methods=['POST'])
def scan_repo():
 
    data = request.get_json()

    
    if not data or 'repo_url' not in data:
        return jsonify({"error": "Missing 'repo_url' field"}), 400

    repo_url = data['repo_url']
    
    #=====
    github_token = data.get('github_token', '')
    if github_token:
        github_token = github_token.strip()

    
    if not repo_url.startswith('https://github.com/') and not repo_url.startswith('git@github.com:'):
        return jsonify({"error": "Only GitHub repositories are supported"}), 400

    #=======
    if github_token and repo_url.startswith('https://github.com/'):
        repo_url = repo_url.replace('https://github.com/', 'https://' + github_token + '@github.com/')

    try:
        
        results = clone_and_scan_repo(repo_url, SCANNER_URL)
        return jsonify(results), 200
        
    except Exception as e:
        #=======
        error_msg = str(e).lower()
        
        if 'repository not found' in error_msg or 'not found' in error_msg or '404' in error_msg:
            return jsonify({"error": "Invalid repository URL. Repository does not exist."}), 404
        
        if 'authentication' in error_msg or 'could not read' in error_msg or 'exit code(128)' in error_msg:
            if not github_token:
                return jsonify({"error": "This repository is private. Please provide a GitHub Personal Access Token."}), 403
            else:
                return jsonify({"error": "Invalid GitHub token. Please check your token."}), 401
        
        return jsonify({"error": "Error: " + str(e)}), 500




@app.route('/scan-local', methods=['POST'])
def scan_local():
    data = request.get_json()

    if not data or 'path' not in data:
        return jsonify({"error": "Missing 'path' field"}), 400

    local_path = data['path']

    try:
        results = scan_local_path(local_path, SCANNER_URL)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# ==========
@app.route('/test-models', methods=['GET'])
def test_models():
    try:
        gemini_key = os.getenv('GEMINI_API_KEY')
        url = "https://generativelanguage.googleapis.com/v1beta/models?key=" + gemini_key
        
        response = requests.get(url, timeout=30)
        print("Models response: " + str(response.status_code))
        print(response.text)
        
        return jsonify(response.json()), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# ==========


# ==========
@app.route('/llm-report', methods=['POST'])
def llm_report():
    data = request.get_json()
    scan_results = data.get('scan_results', {})
    
    try:
        gemini_key = os.getenv('GEMINI_API_KEY')
        if not gemini_key:
            return jsonify({'error': 'GEMINI_API_KEY not set'}), 500
        
        print("API Key loaded")
        
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + gemini_key
        
        # Extract repo info
        repo_url = scan_results.get('repo_url', scan_results.get('path', 'unknown'))
        parts = repo_url.split('/')
        repo_name = parts[-1]
        repo_name = repo_name.replace('.git', '')
        
        summary = scan_results.get('summary', {})
        secrets_count = summary.get('files_with_secrets', 0)
        
        # Adaptive prompts
        if secrets_count == 0:
            prompt = "Scanned " + repo_name + " - no obvious secrets detected.\n\n"
            prompt = prompt + "But analyze:\n"
            prompt = prompt + "1. Any borderline cases? (high entropy strings, suspicious patterns)\n"
            prompt = prompt + "2. Best practices this repo should follow\n\n"
            prompt = prompt + "Scan data:\n" + json.dumps(scan_results, indent=2)
        
        elif secrets_count > 10:
            prompt = repo_name + " has " + str(secrets_count) + " files with secrets.\n\n"
            prompt = prompt + "Priority breakdown:\n"
            prompt = prompt + "1. Most critical leaks (what's the worst case damage?)\n"
            prompt = prompt + "2. Quick wins (easy removals)\n\n"
            prompt = prompt + "Be specific and technical.\n\n"
            prompt = prompt + "Full results:\n" + json.dumps(scan_results, indent=2)
        
        else:
            prompt = "Found secrets in " + str(secrets_count) + " files in " + repo_name + ".\n\n"
            prompt = prompt + "Give me:\n"
            prompt = prompt + "1. What's exposed and where\n"
            prompt = prompt + "2. Impact of each leak type\n"
            prompt = prompt + "3. Prevention checklist (gitignore, pre-commit hooks, etc.)\n\n"
            prompt = prompt + "Keep it actionable.\n\n"
            prompt = prompt + "FORMAT RULES:\n"
            prompt = prompt + "Use clear section headers (FINDINGS, IMPACT, etc.).\n"
            prompt = prompt + "Use bullet points for lists.\n"
            prompt = prompt + "Keep explanations concise and actionable.\n"
            prompt = prompt + "Write in plain text paragraphs - NO markdown formatting symbols.\n\n"
            prompt = prompt + "Scan data:\n" + json.dumps(scan_results, indent=2)
        
        payload = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }]
        }
        
        print("Sending request to Gemini...")
        response = requests.post(url, json=payload, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            candidates = result['candidates']
            first_candidate = candidates[0]
            content = first_candidate['content']
            parts = content['parts']
            first_part = parts[0]
            report_text = first_part['text']
            
            print("Response received successfully")
            return jsonify({'report': report_text}), 200
        else:
            print("API Error: " + str(response.status_code))
            print("Response: " + response.text)
            return jsonify({'error': 'API Error: ' + response.text}), 500
        
    except Exception as e:
        print("Error: " + str(e))
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Error: ' + str(e)}), 500
# ==========

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)