import re
import math
from flask import Flask, request, jsonify

from collections import Counter


app = Flask(__name__)

DETECTORS = {
    "aws_access_key": r'AKIA[0-9A-Z]{16}',
    "aws_secret_key": r'aws(.{0,20})?["\'][0-9a-zA-Z/+]{40}["\']',
    "github_token": r'gh[pousr]_[0-9a-zA-Z]{36,255}',
    "private_key_rsa": r'-----BEGIN RSA PRIVATE KEY-----',
    "private_key_openssh": r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "private_key_dsa": r'-----BEGIN DSA PRIVATE KEY-----',
    "private_key_ec": r'-----BEGIN EC PRIVATE KEY-----',
}

# Entropy thresholds
HIGH_ENTROPY_THRESHOLD = 4
MIN_STRING_LENGTH = 32

def calculate_shannon_entropy_per_character(data: str) -> float:
    if not data:
        return 0.0

    entropy = 0.0
    counts = Counter(data)
    n = len(data)

    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)

    return entropy

def find_high_entropy_strings(content: str) -> list:
    """Find high entropy strings that might be secrets."""
    high_entropy_strings = []
    checked = set()

    # Find any long alphanumeric string (base64-like)
    matches = re.findall(r'([A-Za-z0-9+/=]{32,})', content)

    for match in matches:
        if match in checked or len(match) < MIN_STRING_LENGTH:
            continue
        checked.add(match)

        entropy = calculate_shannon_entropy_per_character(match)
        if entropy > HIGH_ENTROPY_THRESHOLD:
            high_entropy_strings.append({
                "string": match[:MIN_STRING_LENGTH] + "..." if len(match) > MIN_STRING_LENGTH else match,
                "entropy": round(entropy, 2),
                "length": len(match)
            })

    return high_entropy_strings

def scan_content(content: str) -> dict:
    """Scan content for secrets using regex patterns and entropy detection."""
    results = {}

    # Regex-based detectors
    for detector_name, pattern in DETECTORS.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        results[detector_name] = {
            "passed": len(matches) == 0,
            "matches_count": len(matches),
            "matches": matches[:5] if matches else []
        }

    # Entropy-based detector
    high_entropy_matches = find_high_entropy_strings(content)
    results["high_entropy_strings"] = {
        "passed": len(high_entropy_matches) == 0,
        "matches_count": len(high_entropy_matches),
        "matches": high_entropy_matches
    }

    return results

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy"}), 200

@app.route('/scan', methods=['POST'])
def scan():
    """
    Scan a file for secrets.

    Expected JSON body:
    {
        "filename": "path/to/file",
        "content": "file content as string"
    }
    """
    data = request.get_json()

    if not data or 'content' not in data:
        return jsonify({"error": "Missing 'content' field"}), 400

    filename = data.get('filename', 'unknown')
    content = data.get('content', '')

    scan_results = scan_content(content)

    # Check if any detector failed
    has_secrets = any(not result['passed'] for result in scan_results.values())

    response = {
        "filename": filename,
        "has_secrets": has_secrets,
        "detectors": scan_results
    }

    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001, debug=False)
