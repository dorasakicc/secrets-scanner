import pytest
from app import app, scan_content, calculate_shannon_entropy_per_character, find_high_entropy_strings, HIGH_ENTROPY_THRESHOLD

import secrets
import string


@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_aws_access_key_detection():
    """Test Case 1: Verify that AWS access keys are detected by regex patterns."""
    content = """
    # Configuration file
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    database_url = "postgresql://localhost:5432/mydb"
    """
    
    results = scan_content(content)
    
    # Check that AWS access key was detected
    assert results['aws_access_key']['passed'] == False
    assert results['aws_access_key']['matches_count'] > 0
    assert 'AKIAIOSFODNN7EXAMPLE' in str(results['aws_access_key']['matches'])
    
    # Check that other detectors passed (no false positives)
    assert results['github_token']['passed'] == True
    assert results['private_key_rsa']['passed'] == True

def test_entropy_calculation():
    # high entropy strings
    # alphabet = string.ascii_letters + string.digits
    # high_entropy_secret = ''.join(secrets.choice(alphabet) for _ in range(32))
    assert pytest.approx(calculate_shannon_entropy_per_character(""), 0.01) == 0.0
    assert pytest.approx(calculate_shannon_entropy_per_character("ab"), 0.01) == 1.0
    assert pytest.approx(calculate_shannon_entropy_per_character("this is a normal string with low entropy"), 0.01) == 3.75
    assert pytest.approx(calculate_shannon_entropy_per_character("px7OD4p2cVdoC9lf3Ov3sB9vJ3qgUcuz"), 0.01) == 4.53
    assert pytest.approx(calculate_shannon_entropy_per_character("upHxD13VdlBUoEggg4RGqMaZal7jWBR6"), 0.01) == 4.60
    assert pytest.approx(calculate_shannon_entropy_per_character("IdDfh1T200hWyDceijHpTe9RPECVeaBL"), 0.01) == 4.60
    



def test_high_entropy_string_detection():
    """Detect unique strings with high entropy.
    
    """
        
    content = """
    # Some code
    secrets = ["NJsXl86tAr8U9zIwjLu5PLIngRoJ3uJu", "jjPjYDHvZOIxgHx1hSwOJqqZe2vCU95a",\
               "NJsXl86tAr8U9zIwjLu5PLIngRoJ3uJu", "jjPjYDHvZOIxgHx1hSwOJqqZe2vCU95a"]
    normal_string = "this is a normal string with low entropy"
    """
    
    results = scan_content(content)
    
    # Check that high entropy string was detected
    assert results['high_entropy_strings']['passed'] == False
    assert results['high_entropy_strings']['matches_count'] == 2


def test_scan_api_endpoint(client):
    """Test Case 3: Verify the /scan API endpoint handles requests correctly."""
    # Test valid request with secrets
    response = client.post('/scan', json={
        'filename': 'config.py',
        'content': 'github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
    })
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['filename'] == 'config.py'
    assert data['has_secrets'] == True
    assert 'detectors' in data
    assert data['detectors']['github_token']['passed'] == False
    
    # Test invalid request (missing content)
    response = client.post('/scan', json={
        'filename': 'config.py'
    })
    
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert 'content' in data['error'].lower()
    
    # Test request with no secrets
    response = client.post('/scan', json={
        'filename': 'normal.py',
        'content': 'x = 1\ny = 2\nprint("hello world")'
    })
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['has_secrets'] == False
    assert all(detector['passed'] for detector in data['detectors'].values())
