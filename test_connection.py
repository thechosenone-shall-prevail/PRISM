#!/usr/bin/env python3
"""
PRISM Connection Test
Verifies dashboard.html → backend → DB → ML connectivity
"""
import sys
import requests
from pathlib import Path

BACKEND_URL = "http://localhost:8000"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def test_backend_health():
    """Test if backend is running"""
    print(f"\n{YELLOW}[1/6] Testing Backend Health...{RESET}")
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"{GREEN}✓ Backend is online{RESET}")
            print(f"  Version: {data.get('version')}")
            print(f"  ML Model Loaded: {data.get('ml_model_loaded')}")
            print(f"  ML Model Version: {data.get('ml_model_version')}")
            return True
        else:
            print(f"{RED}✗ Backend returned status {response.status_code}{RESET}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"{RED}✗ Cannot connect to backend at {BACKEND_URL}{RESET}")
        print(f"  Make sure backend is running: cd backend && uvicorn main:app --reload")
        return False
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False

def test_authentication():
    """Test authentication endpoint"""
    print(f"\n{YELLOW}[2/6] Testing Authentication...{RESET}")
    try:
        # Test login
        payload = {
            "username": "jk2302@gmail.com",
            "password": "Jk@9176101672"
        }
        response = requests.post(f"{BACKEND_URL}/api/auth/login", json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"{GREEN}✓ Authentication working{RESET}")
            print(f"  User: {data.get('username')}")
            print(f"  Authenticated: {data.get('authenticated')}")
            
            # Test /me endpoint with session
            cookies = response.cookies
            me_response = requests.get(f"{BACKEND_URL}/api/auth/me", cookies=cookies, timeout=5)
            if me_response.status_code == 200:
                me_data = me_response.json()
                print(f"  Session valid: {me_data.get('authenticated')}")
            return True
        else:
            print(f"{RED}✗ Authentication failed with status {response.status_code}{RESET}")
            return False
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False

def test_dashboard_served():
    """Test if login.html is served at root"""
    print(f"\n{YELLOW}[3/6] Testing Dashboard Serving...{RESET}")
    try:
        response = requests.get(BACKEND_URL, timeout=5)
        if response.status_code == 200 and ("Bobo" in response.text or "PRISM" in response.text):
            print(f"{GREEN}✓ Login page is served at {BACKEND_URL}/{RESET}")
            return True
        else:
            print(f"{RED}✗ Dashboard not found at root{RESET}")
            return False
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False

def test_attribution_endpoint():
    """Test attribution API endpoint"""
    print(f"\n{YELLOW}[4/6] Testing Attribution Endpoint...{RESET}")
    try:
        payload = {
            "text": "Spearphishing campaign with PowerShell execution and credential dumping using Mimikatz",
            "input_mode": "analyst_text"
        }
        response = requests.post(f"{BACKEND_URL}/api/analyze", json=payload, timeout=30)
        if response.status_code == 200:
            data = response.json()
            print(f"{GREEN}✓ Attribution endpoint working{RESET}")
            print(f"  Top Group: {data.get('top_group')}")
            print(f"  Confidence: {data.get('confidence_pct')}%")
            print(f"  Techniques: {data.get('technique_count')}")
            return True
        else:
            print(f"{RED}✗ Attribution failed with status {response.status_code}{RESET}")
            print(f"  Response: {response.text[:200]}")
            return False
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False

def test_ml_model():
    """Test ML model is loaded"""
    print(f"\n{YELLOW}[5/6] Testing ML Model...{RESET}")
    model_path = Path("ml/models/prism_model.pkl")
    schema_path = Path("ml/models/feature_schema.json")
    
    if model_path.exists():
        print(f"{GREEN}✓ ML model file exists: {model_path}{RESET}")
    else:
        print(f"{RED}✗ ML model not found: {model_path}{RESET}")
        print(f"  Run: cd ml && python train_model.py")
        return False
    
    if schema_path.exists():
        print(f"{GREEN}✓ Feature schema exists: {schema_path}{RESET}")
    else:
        print(f"{RED}✗ Feature schema not found: {schema_path}{RESET}")
        return False
    
    return True

def test_database_connection():
    """Test database connectivity"""
    print(f"\n{YELLOW}[6/6] Testing Database Connection...{RESET}")
    try:
        # Test profiles endpoint (requires DB)
        response = requests.get(f"{BACKEND_URL}/api/profiles", timeout=10)
        if response.status_code == 200:
            profiles = response.json()
            print(f"{GREEN}✓ Database connected{RESET}")
            print(f"  APT Profiles loaded: {len(profiles)}")
            return True
        else:
            print(f"{YELLOW}⚠ Database may not be configured{RESET}")
            print(f"  Status: {response.status_code}")
            return False
    except Exception as e:
        print(f"{YELLOW}⚠ Database connection issue: {e}{RESET}")
        print(f"  Check backend/.env for Supabase credentials")
        return False

def main():
    print(f"\n{'='*60}")
    print(f"  PRISM Connection Test")
    print(f"{'='*60}")
    
    results = []
    results.append(("Backend Health", test_backend_health()))
    results.append(("Authentication", test_authentication()))
    results.append(("Dashboard Serving", test_dashboard_served()))
    results.append(("Attribution API", test_attribution_endpoint()))
    results.append(("ML Model", test_ml_model()))
    results.append(("Database", test_database_connection()))
    
    print(f"\n{'='*60}")
    print(f"  Test Summary")
    print(f"{'='*60}")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = f"{GREEN}✓ PASS{RESET}" if result else f"{RED}✗ FAIL{RESET}"
        print(f"  {name:.<40} {status}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print(f"\n{GREEN}🎉 All systems operational!{RESET}")
        print(f"\n  Login Page: {BACKEND_URL}/")
        print(f"  Credentials: jk2302@gmail.com / Jk@9176101672")
        print(f"  API Docs:   {BACKEND_URL}/docs")
        return 0
    else:
        print(f"\n{YELLOW}⚠ Some tests failed. Check errors above.{RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
