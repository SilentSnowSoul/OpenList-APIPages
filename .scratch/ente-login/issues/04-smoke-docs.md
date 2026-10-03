# 04: 冒烟脚本与文档

**Status:** blocked
**Type:** task

## Question

真实 museum 冒烟 + 文档收尾。

## Notes

- env-gated 手动脚本(如 `scripts/test-ente-login.mjs`,对齐仓库脚本惯例):走完整 SRP(+TOTP/OTP)→ 打印 Worker 驱动四字段;凭证经 env 注入,不硬编码。默认官方 endpoint,可 `ENTE_API` 覆盖(自托管 quickstart)。
- README:项目说明/驱动能力列表加 Ente;说明纯前端、后端零配置、无新增环境变量。
- 回归确认:`src/index.ts` 无 ente 路由;浏览器直连按用户 IP 计数,公共部署无共享 IP 限流风险。

## Acceptance

- 对官方 endpoint 真实账号冒烟通过,输出凭证可被 OpenList-Worker `ente` 驱动挂载成功(跨仓库手动验证,记录在 Answer)。
- README 更新合入。

## Answer

**本仓库内可验证的部分已完成:**

- `scripts/test-ente-login.mjs` 存在,env-gated(`ENTE_EMAIL`/`ENTE_PASSWORD` 缺失时跳过并以 0 退出),支持 `ENTE_API` / `ENTE_OTP` / `ENTE_TOTP` 覆盖;OTP 路径已补 `2fa_required` 分支(email-MFA + TOTP 账号)。
- README「开发与验证」记录了冒烟命令。核查结论:README 写的 `npm run test-ente` **并非死命令**——该脚本由根 `package.json` 提供(此前误判为缺失,曾在 `frontend/package.json` 补同名脚本,已回退以免与根脚本重复分叉)。真正的缺口是 README 未说明需在**仓库根目录**执行;已补该说明并实跑确认可解析、无凭证时正常跳过。

**验收项未完成(阻塞,未伪造):**

- 未对官方 endpoint 真实账号执行冒烟:本环境没有 ente 账号凭证,且出网受限(HTTPS 克隆/抓取被拒)。因此
  - 「真实账号冒烟通过」未验证;
  - 「输出凭证可被 OpenList-Worker `ente` 驱动挂载成功」未验证。
- 该验收必须在有真实账号的机器上手动执行后回填;在那之前本票据不得标记完成。SRP/2FA 分支的正确性目前只有单元测试与固定向量(含 `github.com/ente/go-srp` fork 生成的 golden 向量)支撑,不能替代真实账号验证。
