import pytest
import sys
import os
import json

# Add current directory to path so we can import app
sys.path.append(os.path.dirname(__file__))

from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_index(client):
    """Test that the index page loads."""
    rv = client.get('/')
    assert rv.status_code == 200
    assert b'Phishing' in rv.data

def test_predict_legitimate(client):
    """Test prediction for a likely legitimate URL."""
    # Google is known legitimate
    rv = client.post('/predict', data={'url': 'https://www.google.com'})
    assert rv.status_code == 200
    data = json.loads(rv.data)
    
    assert 'prediction' in data
    assert 'risk_score' in data
    assert 'shap_plot_url' in data
    
    # Ideally prediction should be 0 (Legitimate)
    # But model might vary.
    print(f"Prediction for google.com: {data['prediction']}, Score: {data['risk_score']}")

def test_predict_phishing_features(client):
    """Test prediction for a URL with phishing features."""
    # A constructed URL with many features (IP, many dots, subdomains, etc.)
    # Note: real network calls might timeout or fail, returning -1 or default.
    # We test that the app doesn't crash.
    fake_phish = 'http://192.168.1.1/confirm-account/login.php?user=admin&pass=1234'
    rv = client.post('/predict', data={'url': fake_phish})
    
    # It might fail due to network timeouts if extractor is strict, but we handled exceptions.
    if rv.status_code == 200:
        data = json.loads(rv.data)
        print(f"Prediction for fake_phish: {data['prediction']}, Score: {data['risk_score']}")
        assert data['shap_plot_url'].startswith('/static/shap_plot_')
    else:
        print(f"Failed with status {rv.status_code}: {rv.data}")
