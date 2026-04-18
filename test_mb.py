import requests

API_KEY = "e39e2b619fd686f43243d2d7ec8c42b897aff0cb51901772"
# We will use the hash from your earlier logs that we know exists
TEST_HASH = "8fe251310c0aa4c0f9db89968be2d94b33de903b7b807dd18d5f40cfc5f73587"

print(f"[*] Testing MalwareBazaar auth with key ending in: ...{API_KEY[-4:]}")

resp = requests.post(
    "https://mb-api.abuse.ch/api/v1/",
    data={"query": "get_file", "sha256_hash": TEST_HASH},
    headers={"API-KEY": API_KEY}
)

print(f"[*] HTTP Status: {resp.status_code}")

if resp.status_code == 200:
    if resp.content.startswith(b"PK"):
        print("[+] SUCCESS! The key is valid and the payload downloaded.")
    else:
        print("[-] Authenticated, but received a JSON error:")
        print(resp.json())
else:
    print("[-] AUTHENTICATION FAILED. The server rejected this exact key.")
    print(resp.text)
