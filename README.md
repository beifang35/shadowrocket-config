# 小火箭（Shadowrocket）合并配置

把「白名单过滤 + 广告过滤」与「加密 DoH + DNS 防泄漏 + ACL4SSR 分流」编译合并成一份配置，同时保留双方能力，并由 GitHub Actions 每日自动同步上游更新。

---

## 目录

| 文件 | 用途 |
|---|---|
| [shadowrocket.conf](shadowrocket.conf) | 当前线上配置（634 KB / 17,223 行内联 + 14 个远程规则集，展开后 333,268 条规则） |
| [rules/anti-ad.txt](rules/anti-ad.txt) | 预清洗的 `DOMAIN-SET` 广告域名集（anti-AD ∪ Johnshall Reject，108,722 条唯一域名） |
| [merge.py](merge.py) | 合并编译器：拉取 4 路上游 → 规则去重与误杀清洗 → 按优先级分层 → 16 项发布闸门校验 |
| [verify.py](verify.py) | 静态深度验收：11 项结构检查 + 93 条核心断言 + GFWList（4,062 条）与国内域名（109,455 条）全量扫描 |
| [verify_live.py](verify_live.py) | 二轮实时验收：支持直接读取小火箭 `shadowrocket.db` 或编译产物（`--conf`），执行 76 项分流 + 1,218 条广告抽检 + DNS 零泄漏验证 |
| [publish.sh](publish.sh) | 一键发布：合并 → 校验 → commit → 打 tag → push → 刷新 CDN 缓存 |

---

## 30 秒上手

```bash
# 1. 拉取上游并重新编译（内置 16 项闸门校验）
python3 merge.py

# 2. 运行全量静态验收与二轮实时验收
python3 verify.py
python3 verify_live.py --conf

# 3. 一键发布到 GitHub Pages 与 jsDelivr
./publish.sh
```

发布完 1–2 分钟，小火箭里「更新配置」即可拉到最新版本。

---

## 订阅地址

| 优先级 | 地址 | 生效速度 |
|---|---|---|
| ① | `https://beifang35.github.io/shadowrocket-config/shadowrocket.conf` | push 后 1–2 分钟（推荐） |
| ② | `https://cdn.jsdelivr.net/gh/beifang35/shadowrocket-config@latest/shadowrocket.conf` | 国内可达（带 tag 刷新） |
| ③ | `https://raw.githubusercontent.com/beifang35/shadowrocket-config/main/shadowrocket.conf` | 需代理 |

---

## 数据来源

- [Johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever)（活跃维护版白名单 + 广告过滤，每日更新）
- [h2y/Shadowrocket-ADBlock-Rules](https://github.com/h2y/Shadowrocket-ADBlock-Rules)（经典 EasyList 16,148 条广告底座）
- [DuskWander87/shadowrocket-config](https://github.com/DuskWander87/shadowrocket-config)（DNS 防泄漏架构，MIT）
- [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules)（`reject.txt` 广告域名集，19.7 万条）
- [anti-AD](https://github.com/privacy-protection-tools/anti-AD)（国内 App 埋点/广告拦截，每日更新）
- [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR)（分流规则集，CC-BY-SA-4.0）
