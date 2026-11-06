# 小火箭（Shadowrocket）合并配置

把「白名单过滤 + 广告过滤」与「加密 DoH + DNS 防泄漏 + ACL4SSR 分流」编译合并成一份配置，同时保留双方能力，并由 GitHub Actions 每日自动同步上游更新。

---

## 目录

| 文件 | 用途 |
|---|---|
| [shadowrocket.conf](shadowrocket.conf) | 合并配置（内联规则 + 14 个远程规则集；展开数量随上游更新变化） |
| [rules/anti-ad.txt](rules/anti-ad.txt) | 预清洗的 `DOMAIN-SET` 广告域名集（anti-AD ∪ Johnshall Reject，108,722 条唯一域名） |
| [merge.py](merge.py) | 合并编译器：拉取 4 路上游 → 规则去重与误杀清洗 → 按优先级分层 → 发布闸门校验（含 DNS 端口保护，当前 20 项） |
| [verify.py](verify.py) | 静态深度验收：结构、分流与兼容断言，GFWList 与国内域名表全量扫描；取源失败、空规则与空扫描均阻断发布 |
| [verify_live.py](verify_live.py) | 数据库配置快照或编译产物（`--conf`）的静态验收，加主/节点/回退 DoH 报文和解析结果探测 |
| [verify_support.py](verify_support.py) | 共用取源、规则格式、关键兼容用例与 DNS wire response 校验 |
| [publish.sh](publish.sh) | 一键发布：合并 → 校验 → commit → 打 tag → push → 刷新 CDN 缓存 |

---

## 30 秒上手

```bash
# 1. 拉取上游并重新编译（内置发布闸门校验，不通过不写文件）
python3 merge.py

# 2. 运行负例回归、全量静态验收与 DoH 探测
python3 -m unittest discover -s tests -p 'test_verify*.py'
python3 verify.py
python3 verify_live.py --conf

# 3. 一键发布到 GitHub Pages 与 jsDelivr
./publish.sh
```

发布完 1–2 分钟，小火箭里「更新配置」即可拉到最新版本。

本地发布脚本和每日工作流均在同步、提交前运行负例回归与 `verify.py`，失败即停止。`verify_live.py` 的 DoH 请求由验收进程发起；数据库快照和静态匹配不证明客户端实际 DNS 出口、浏览器指纹或 WebRTC 泄漏状态，后者仍需独立抓包与浏览器验收。

**WebRTC 运行设置**：每台设备都需在 Shadowrocket 的「设置 → UDP」中保持「启用转发」，并开启「禁用 STUN」。STUN 域名黑名单无法覆盖硬编码 IP；本机实测曾由国内 STUN IP 获得运营商真实 IP，开启原生限制后该路径不再返回公网候选。这个开关属于设备设置，不会随配置订阅自动同步，也不等于已验证全部音视频通话兼容性。

**iOS IPv6 接管设置**：订阅中的 `ipv6 = false`、`prefer-ipv6 = false` 不能作为 iOS 已关闭系统 IPv6 或已防住旁路的证明。若开启全局代理后，检测仍取得本地运营商的 IPv6，请在手机「设置 → 隧道」开启「包括所有网络」，「包括本地网络」保持关闭；回到「配置」路由模式，断开并重新连接 VPN，再重启浏览器复测。这与「禁用 STUN」都属于设备设置，每台手机需要独立检查，更新订阅不能代替设置和复测。该接管选项仍有系统服务例外，见 [Apple 路由说明](https://developer.apple.com/documentation/networkextension/nevpnprotocol/includeallnetworks)。

**Chrome 防追踪边界**：内容拦截器可补充 URL、页面资源及已知指纹库过滤；域名规则和内容规则不能保证阻止所有第一方内联或改名自托管指纹采集。不要以测试页变绿代替实际验收，也不要叠加全网 Canvas、WebGL、字体、音频原型伪装脚本。

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
