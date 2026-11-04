# Shadowrocket 合并配置

把两份互不兼容的小火箭配置编译成一份，**同时保留双方的全部能力**：

| 来源 | 提供什么 |
|---|---|
| [h2y/Shadowrocket-ADBlock-Rules](https://github.com/h2y/Shadowrocket-ADBlock-Rules) · `sr_top500_whitelist_ad.conf`（白名单过滤 + 广告过滤） | 16148 条广告拦截 + 338 条直连白名单 + 60 条强制代理名单 |
| [DuskWander87/shadowrocket-config](https://github.com/DuskWander87/shadowrocket-config) · DNS 防泄漏 | 加密 DoH、节点域名专用 DNS、ACL4SSR 国内分流、防 DNS rebinding |

---

## 订阅地址

**主用 jsDelivr `@latest`（国内可直连，已验证）**：

```
https://cdn.jsdelivr.net/gh/beifang35/shadowrocket-config@latest/shadowrocket.conf
```

**备用 raw（需能访问 GitHub，CDN 有几小时缓存延迟）**：

```
https://raw.githubusercontent.com/beifang35/shadowrocket-config/main/shadowrocket.conf
```

> ⚠️ **不要用 `@main`**。jsDelivr 对分支引用缓存 12 小时，改了也拉不到新版。
> `@latest` 指向最新 tag，每次发布都会打新 tag，能立刻解析到新内容。
>
> 如果 `@latest` 拉到的还是旧版本，访问一次下面的地址强制刷缓存：
> `https://purge.jsdelivr.net/gh/beifang35/shadowrocket-config@latest/shadowrocket.conf`

### 使用方法

1. 小火箭 → 底栏「配置」→ 右上角 `+` → 粘贴订阅地址 → 下载
2. 长按该配置 → **使用配置**
3. 首页 → 「全局路由」→ 选 **配置**

3 步缺一不可。只下载不启用 = 没生效。

---

## 为什么不能直接把两份配置叠加

小火箭虽然有 `include`（扩展配置），但只做「继承」：不去重、不重排。这两份配置的冲突是结构性的：

| 冲突点 | 白名单+广告 | DNS 防泄漏 | 直接叠加的后果 |
|---|---|---|---|
| `dns-server` | `system, 114.114.114.114, ...` | 加密 DoH | 谁生效取决于叠加顺序，`system` 那一半永远是明文泄露 |
| `GEOIP,CN` | `DIRECT`（无 `no-resolve`） | `DIRECT,no-resolve` | 前者先命中 → 每个域名都触发本地解析 → 防泄漏失效 |
| `FINAL` | `FINAL,PROXY` | `FINAL,PROXY` | 两条只能活一条，另一条永远匹配不到 |
| 局域网排除 | `bypass-tun`（2021 年旧键名） | `tun-excluded-routes` | 新版本小火箭不认，局域网直连排除失效 |

所以只能在合并阶段一次性编译好，「include」解决不了。

---

## 合并后的规则顺序

按**首条匹配生效**排列，顺序即优先级：

```
1. Apple 直连（ACL4SSR Apple.list）        ← 必须最早，否则 App Store / iCloud 被广告规则误伤
2. 广告拦截 · A 的 16148 条                ← EasyList 系，主力
3. 广告拦截 · B 的 Reject.list（55 条）
4. 广告拦截 · B 的 BanAD + BanProgramAD    ← 补 2021 年之后的新广告
5. 直连白名单 · A 的 338 条
6. 强制代理 · A 的 60 条
7. 国内直连 · B 的 ChinaDirect + 国内域名/流媒体/企业 IP/IP 段
8. A 的 124 条 IP 段（统一补 no-resolve）
9. GEOIP,CN,DIRECT,no-resolve              ← 全场唯一一条
10. FINAL,PROXY                            ← 全场唯一一条
```

### DNS 段（合并后）

```ini
dns-server        = https://dns.alidns.com/dns-query, https://doh.pub/dns-query, https://223.5.5.5/dns-query
proxy-dns-server  = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
fallback-dns-server = https://1.12.12.12/dns-query
```

- `dns-server`：直连类域名的解析，走加密 DoH
- `proxy-dns-server`：**节点/机场域名的解析**，独立加密，不让运营商明文看到你在连哪个机场
- `fallback-dns-server`：加密 DNS 全部失败时的备用
- **保险丝**：如果所有加密 DNS 都不通导致断网，把 `fallback-dns-server` 改成 `system` 即可恢复

---

## 验证是否真的生效

小火箭 → **数据 → 代理 → DNS → 启用日志记录**，然后 **数据 → DNS** 看记录：

| 观察 | 结论 |
|---|---|
| 直连域名的「处理 DNS」显示 `dns.alidns.com` / `doh.pub` | 加密 DNS 生效 |
| 境外域名**不出现在日志里** | 正常，代理类域名由节点远端解析 |
| 境外域名出现，且处理 DNS 是本地运营商 IP（`202.96.x.x` 等） | 泄露，检查 `GEOIP` 是否带 `no-resolve` |
| 某条响应 > 2 秒 | 正在走备用 DNS，主 DNS 可能不稳 |

网页测的话用 `dnsleaktest.com`，但**别看错**：显示「DNS 在海外」是正常的（节点在解析），显示**本地运营商的 DNS** 才是泄露。

---

## 更新

上游任何一个源变化后，在本仓库根目录执行：

```bash
./publish.sh
```

脚本会依次完成：

1. 重新拉取两个上游配置
2. 重新合并
3. **跑 10 项校验**（任何一项不过就终止，不覆盖线上版本）
4. push 到本仓库
5. 清 jsDelivr 缓存

小火箭侧：长按配置 → 「更新配置」，或在 `ⓘ → 自动更新` 里开启自动拉取。

### 校验清单（防止上游改坏时把可用配置冲掉）

- A 的广告规则数量 ≥ 10000（防上游内容被清空）
- B 的 11 个规则集全部存在（防某个 RULE-SET 被删）
- `FINAL` 只有一条
- `GEOIP` 只有一条且带 `no-resolve`
- 没有 `dns-server = system`
- DNS 走加密 DoH
- `proxy-dns-server` 存在
- 所有 `IP-CIDR` / `GEOIP` 规则都带 `no-resolve`
- 总规则数 > 10000

---

## 上游状态

| 源 | 状态 | 最后更新 |
|---|---|---|
| h2y/Shadowrocket-ADBlock-Rules | **已归档** | 2021-03-29 构建，2021-04-12 归档 |
| DuskWander87/shadowrocket-config | 活跃 | 2026-10-30 |

A 已停止维护，规则停留在 2021 年；B 仍在更新，实际跟进的是 B。

---

## 广告拦截规模

| 来源 | 条数 |
|---|---|
| A · h2y 白名单+广告（EasyList 系，2021） | 16,148 |
| **anti-AD**（国内 App 埋点/广告，2026-11 更新） | **101,785** |
| B · Reject.list + BanAD + BanProgramAD | 1,189 |

展开后规则链总计 **128,684 条**。

> 为什么必须加 anti-AD：h2y 那份是 2021 年归档的，只有 1.6 万条广告规则。
> 实测对比你原来在用的配置，它拦截了 60,871 个广告域名——用 h2y 单干会少掉 4.4 万条。
> anti-AD 交叉验证：10.9 万个国内常用域名里，一线站点（百度/淘宝/QQ/B站/支付宝/微信…）命中 0 个。

---

## 强制代理覆盖层（40 个域名）

A 是 2021 年的配置，它把一批境外站点判成「可直连」。用 GFWList（4062 条被墙域名）交叉比对后，
发现 **37 个命中**——按 A 原样走直连会直接打不开：

```
github.com/github.io/githubusercontent.com    ← 本机 vault 的 git 同步依赖它
speedtest.net                                 ← 判直连会导致测速测的是本地带宽
linkedin.com  spotify.com  imgur.com  naver.com  daum.net  yahoo.com
9gag.com  behance.net  canva.com  deviantart.com  etsy.com  feedly.com
forbes.com  godaddy.com  goodreads.com  mega.nz  nicovideo.jp  dmm.co.jp
ameblo.jp  namu.wiki  pandora.com  roblox.com  rutracker.org  wikia.org
theguardian.com  washingtonpost.com  weebly.com  xfinity.com  youporn.com
bet365.com  avg.com  hola.com  homedepot.com  huffingtonpost.com  flipkart.com
```

合并时插在 A 的 Direct 白名单**之前**（`merge.py` 里 `put(15, ...)`），压住 A 的判断。
想关掉某一项：从 `merge.py` 的 `FORCE_PROXY` 里删掉那行，重跑 `./publish.sh`。

---

## 验收方法

配置当代码测，不靠人工点几下：

```bash
python3 verify.py        # 46 条断言 + GFWList/国内域名全量扫描 + 10 项结构检查
```

`verify.py` 实现的是小火箭的真实语义：

- **首条匹配生效**（first-match-wins）
- **`no-resolve` 对域名请求跳过 IP 类规则**，不触发本地 DNS 查询
- 反向：**没带 `no-resolve` 的 IP 规则会让每个域名都本地解析一次**，这是 DNS 泄露的唯一技术成因

它会给每条测试流量打出「最终策略」和「匹配过程中触发了几次本地 DNS 查询」。
理想结果是 **0 次**——一旦 >0，泄露就已经发生，后面匹配到什么都救不回来。

---

## 已知取舍

1. **A 的 124 条 IP 段规则统一补了 `no-resolve`**
   代价：这些 IP 段不再拦截域名请求（只匹配 IP 直连）。换来的是任何域名都不会因为这些规则触发本地 DNS 查询。域名级广告规则已有 1.6 万条覆盖，影响很小。

2. **`app.adjust.com` 会被 A 拦掉**
   A 拦的是 `adjust.com` 整个后缀，B 的 ChinaDirect 单独放行了 `app.adjust.com`。合并时以手机端广告拦截优先。Adjust 是广告归因 SDK，不影响正常使用。

3. **两条规则冲突极小**
   实测交叉比对：A 拦 / B 直连 4 条（`jiathis.com`、`koowo.com`、`tencentmind.com`、`adjust.com→app.adjust.com`），A 直连 / B 拦广告 3 条（`51yes.com`、`cnzz.com`、`popads.net`）。全部是广告/统计域名。

---

## 致谢

- [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) —— 分流规则集（CC-BY-SA-4.0）
- [h2y/Shadowrocket-ADBlock-Rules](https://github.com/h2y/Shadowrocket-ADBlock-Rules) —— 白名单 + 广告过滤
- [DuskWander87/shadowrocket-config](https://github.com/DuskWander87/shadowrocket-config) —— DNS 防泄漏基线与排查经验（MIT）
