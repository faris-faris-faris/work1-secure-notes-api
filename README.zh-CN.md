# 实验一：安全 REST API 开发、CI/CD 与真实 CVE 漏洞分析

本仓库是 HDU《信息安全》课程实验一的实现：一个用 Node.js + Express 编写的校园公告板
API（与旧版 Flask 实验代码完全不同），配套 SAST/SCA 流水线，以及 **CVE-2022-22965
（Spring4Shell）** 的复现、根因分析与修复验证。

> 中文完整报告见 [`docs/report_zh.pdf`](docs/report_zh.pdf)（Markdown：
> [`docs/report_zh.md`](docs/report_zh.md)）；英文版见
> [`docs/report_en.pdf`](docs/report_en.pdf)。

| 项目 | 说明 |
|---|---|
| 技术栈 | Node.js 22+ / Express 5 / SQLite（`node:sqlite`） |
| 认证 | scrypt 口令哈希 + HS256 JWT + 可轮换刷新令牌 |
| SAST | ESLint + `eslint-plugin-security` |
| SCA | CI 中 `npm audit`，本地 OSV.dev（`scripts/sca-osv.mjs`） |
| 测试 | 52 个 `node:test` 用例，行覆盖率 96.7% |
| CVE | **CVE-2022-22965**，Spring MVC 数据绑定 RCE（CVSS 9.8） |

## 快速开始

```bash
npm install
npm start                 # http://127.0.0.1:3000
```

```powershell
# 16 项端到端检查（登录、401、SQLi、XSS、越权、刷新重放、锁定）
powershell -ExecutionPolicy Bypass -File .\scripts\run-demo.ps1

# 与 ci.yml 相同的四个 job：test / lint / sast / sca
powershell -ExecutionPolicy Bypass -File .\scripts\ci-local.ps1
```

演示账号（仅实验用）：`alice / Passw0rd!Alice`（管理员）、`bob / Passw0rd!Bob`。

## API

| 方法 | 路径 | 认证 | 作用 |
|---|---|---|---|
| POST | `/auth/login` | — | 登录，返回访问令牌与刷新令牌 |
| GET | `/api/data` | Bearer | 公告列表（`limit`、`offset`、`q`、`category`、`sort`） |
| POST | `/api/notes` | Bearer | 发布公告（自选方法） |
| GET/PATCH/DELETE | `/api/notes/:id` | Bearer | 读取 / 修改 / 删除（作者或管理员） |
| POST | `/auth/refresh` | — | 轮换刷新令牌 |
| POST | `/auth/logout` | — | 吊销刷新令牌 |
| GET | `/api/me` | Bearer | 当前身份 |
| GET | `/health` | — | 存活探测 |

## 安全要点

* **SQLi**：全部使用绑定参数；`LIKE` 通配符单独转义；`ORDER BY` 只能取白名单值。
* **XSS**：数据库保存原文，响应时统一 HTML 转义；配合 CSP、`nosniff` 与严格校验。
* **认证**：scrypt（N=2¹⁵）+ HS256 JWT（算法固定、校验 iss/aud/exp）+ 刷新令牌轮换与
  重放检测；登录限速与防用户枚举。
* **访问控制**：写操作必须通过“作者或管理员”检查，防止 IDOR。

## CVE-2022-22965

```bash
cd cve
docker compose up -d                     # 漏洞环境：Spring 5.3.17 / Tomcat 8.5.77
powershell -ExecutionPolicy Bypass -File .\exploit.ps1

docker compose down
docker compose -f docker-compose.fixed.yml up -d --build   # 修复：Spring 5.3.18
powershell -ExecutionPolicy Bypass -File .\verify-fix.ps1
```

漏洞请求通过 `class.module.classLoader.resources.context.parent.pipeline.first`
改写 Tomcat 访问日志 Valve，把日志写成 webroot 下的 JSP webshell，随后执行命令
（实测 `uid=0(root)`）。修复后同样请求被静默忽略（HTTP 200），但不再产生任何文件、
访问日志格式不变、正常参数绑定仍有效——因此验证基于**行为**而非状态码。

详细分析： [`cve/README.md`](cve/README.md)。

## 目录

```
src/            应用代码（app、config、db、security、validation、routes）
tests/          52 个测试
scripts/        demo、ci-local、sast-summary、sca-osv、render_png、build_report
cve/            漏洞环境、利用脚本、补丁、验证脚本
docs/           中英文报告（md/html/pdf）、证据记录、截图、提交说明
.github/        ci.yml（test / lint / sast / sca）
```

## 提交信息

报告封面已填写姓名 **Wu ZiYang** 与 HDU 学号 **23320121**；变体号未分配（—）。
仓库已公开，最近一次成功流水线：
<https://github.com/faris-faris-faris/work1-secure-notes-api/actions/runs/40105508780>
（提交 `7748614`，test/lint/sast/sca 全部通过）。

## 参考

* OWASP Top 10 — <https://owasp.org/www-project-top-ten/>
* Vulhub `spring/CVE-2022-22965` — <https://github.com/vulhub/vulhub/tree/master/spring/CVE-2022-22965>
* NVD — <https://nvd.nist.gov/vuln/detail/CVE-2022-22965>

> 仓库中的演示账号与密钥仅用于一次性实验环境，不得在实验之外复用。
