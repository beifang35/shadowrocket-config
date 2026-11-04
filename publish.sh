#!/bin/bash
# 一键更新并发布
#   ./publish.sh            重新合并 -> 校验 -> commit -> 打 tag -> push -> 清 CDN 缓存
#   ./publish.sh --dry-run  只合并校验，不发布
set -euo pipefail

cd "$(dirname "$0")"
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

export GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no -i ${HOME}/.ssh/id_ed25519_beifang35"
GIT="git -c user.name=beifang35 -c user.email=beifang35@users.noreply.github.com"

echo "==> 1/5 重新合并并校验"
if ! python3 merge.py; then
  echo ""
  echo "!! 校验未通过，已终止。线上版本保持不变。"
  echo "   详情见 out/merge-report.txt"
  exit 1
fi

echo ""
echo "==> 2/5 同步到仓库根目录"
cp out/shadowrocket.conf ./shadowrocket.conf
echo "    shadowrocket.conf  $(wc -c < shadowrocket.conf | tr -d ' ') 字节 / $(wc -l < shadowrocket.conf | tr -d ' ') 行"

if [[ $DRY -eq 1 ]]; then
  echo ""
  echo "==> dry-run，跳过发布"
  exit 0
fi

echo ""
echo "==> 3/5 提交"
$GIT add -A
if $GIT diff --cached --quiet; then
  echo "    内容无变化，跳过 commit"
  CHANGED=0
else
  $GIT commit -q -m "chore: 更新合并配置 $(date '+%Y-%m-%d %H:%M')"
  CHANGED=1
  echo "    已提交 $(git rev-parse --short HEAD)"
fi

# 打新 tag —— 订阅 URL 用 @latest，jsDelivr 的分支引用（@main）缓存 12 小时，
# 只有 tag 引用能立即解析到新内容
if [[ $CHANGED -eq 1 ]]; then
  LAST=$(git tag -l 'v*' | sed 's/^v//' | sort -V | tail -1)
  if [[ -z "$LAST" ]]; then
    NEXT="1.0.0"
  else
    MAJOR=$(echo "$LAST" | cut -d. -f1)
    MINOR=$(echo "$LAST" | cut -d. -f2)
    PATCH=$(echo "$LAST" | cut -d. -f3)
    NEXT="${MAJOR}.${MINOR}.$((PATCH + 1))"
  fi
  echo "    打 tag v${NEXT}"
  git tag -f "v${NEXT}"
fi

echo ""
echo "==> 4/5 推送到 GitHub"
git push origin main
[[ $CHANGED -eq 1 ]] && git push -f origin "v${NEXT}"
echo "    已推送"

echo ""
echo "==> 5/5 清除 jsDelivr 缓存"
for ref in latest main "v${NEXT:-1.0.0}"; do
  curl -sS -m 20 "https://purge.jsdelivr.net/gh/beifang35/shadowrocket-config@${ref}/shadowrocket.conf" >/dev/null \
    && echo "    已清 @${ref}" || echo "    清 @${ref} 失败（不影响 raw，重启后自然过期）"
done

echo ""
echo "完成。"
echo "  订阅地址 https://cdn.jsdelivr.net/gh/beifang35/shadowrocket-config@latest/shadowrocket.conf"
echo "  小火箭里长按配置 -> 更新配置 即可拉到新版。"
