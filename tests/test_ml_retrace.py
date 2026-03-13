import requests
import os

API_URL = "http://localhost:8000/api/retrace"

def test_retrace():
    print("Testing Unified ML Attribution...")
    # Using a dummy PE header string to trigger PE parsing
    dummy_pe = b"MZ" + b"\x00" * 1024
    
    files = {'file': ('test_malware.exe', dummy_pe)}
    data = {'hash_value': ''}
    
    try:
        response = requests.post(API_URL, files=files, data=data)
        if response.status_code == 200:
            res = response.json()
            print("\n[SUCCESS] API Response received.")
            print(f"Top Match: {res['top_match']['family']}")
            print(f"Confidence: {res['top_match']['confidence_pct']}%")
            print(f"ML Version: {res['ml_metadata']['version']}")
            print(f"Indicators: {len(res['top_match']['matched_indicators'])}")
            
            if res['top_match']['matched_indicators']:
                print("Top Indicators (SHAP):")
                for ind in res['top_match']['matched_indicators']:
                    print(f"  - {ind}")
        else:
            print(f"\n[FAILED] Status {response.status_code}: {response.text}")
    except Exception as e:
        print(f"\n[ERROR] {e}")

if __name__ == "__main__":
    test_retrace()
