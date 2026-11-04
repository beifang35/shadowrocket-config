#!/bin/bash
# 一键更新并发布
#   ./publish.sh            重新合并 -> 校验 -> push -> 清 CDN 缓存
#   ./publish.sh --dry-run  只合并校验，不 push
set -euo pipefail

cd "$(dirname "$0")"
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

echo "==> 1/4 重新合并并校验"
if ! python3 merge.py; then
  echo ""
  echo "!! 校验未通过，已终止。线上版本保持不变。"
  echo "   详情见 out/merge-report.txt"
  exit 1
fi

echo ""
echo "==> 2/4 发布到仓库根目录"
cp out/shadowrocket.conf ./shadowrocket.conf
SIZE=$(wc -c < shadowrocket.conf | tr -d ' ')
LINES=$(wc -l < shadowrocket.conf | tr -d ' ')
echo "    shadowrocket.conf  ${SIZE} 字节 / ${LINES} 行"

if [[ $DRY -eq 1 ]]; then
  echo ""
  echo "==> dry-run，跳过 push"
  exit 0
fi

echo ""
echo "==> 3/4 推送到 GitHub"
git add -A
if git diff --cached --quiet; then
  echo "    内容无变化，跳过 commit"
else
  git commit -m "chore: 更新合并配置 $(date '+%Y-%m-%d %H:%M')"
  git push origin main
  echo "    已推送"
fi

echo ""
echo "==> 4/4 清除 jsDelivr 缓存"
for f in shadowrocket.conf; do
  curl -sS -m 20 "https://purge.jsdelivr.net/gh/beifang35/shadowrocket-config@main/${f}" \
    && echo "" || echo "    清缓存请求失败（不影响 raw，jsDelivr 会在 12 小时后自然过期）"
done

echo ""
echo "完成。小火箭里长按配置 -> 更新配置 即可拉到新版。"
