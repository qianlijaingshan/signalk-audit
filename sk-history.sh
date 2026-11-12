#!/bin/bash
# 打印三个镜像里带 chmod u+s 的构建层（时间统一换成 UTC，方便和文章里的时间对）
for img in v2.36.0-core v2.37.0-core v2.37.0; do
  printf "%-14s " "$img"
  docker history --no-trunc --format '{{.CreatedAt}}|{{.Size}}|{{.CreatedBy}}' "signalk/signalk-server:$img" \
    | grep 'groupadd -r docker' \
    | python3 -c 'import sys
from datetime import datetime, timezone
for l in sys.stdin:
    c, s, b = l.split("|", 2)
    dt = datetime.fromisoformat(c.strip().replace("Z", "+00:00")).astimezone(timezone.utc)
    print(dt.strftime("%Y-%m-%dT%H:%M:%SZ"), s.strip().rjust(6), " " + b.strip()[-38:])'
done
