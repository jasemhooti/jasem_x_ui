# jasem_x_ui — shared contract for all agents

Fork of 3x-ui **v3.8.5** (branch `jasem`). Every agent reads this file and
`CLAUDE.md` (repo rules: 2-line comment max, stdlib tests, i18n in all 13
locales, endpoints.ts for new routes). If this file and your instinct
disagree, this file wins. If you need something outside your ownership, do
NOT edit it — write it under "Requests to lead" in your final report.

## Goals
1. Fresh install runs **Xray-core v26.6.27 by default**; the admin can still
   switch cores from the dashboard. The panel must work on 26.6.27 even though
   3.8.5 writes keys for 26.9.9.
2. Any config / subscription can become an outbound: share links of every
   common scheme, plus Clash YAML, sing-box JSON and Xray JSON subscription
   bodies. Protocols xray lacks run through a **sing-box v1.14.2** sidecar.
3. Optional TLS fragment per outbound and per subscription.
4. Branding `jasem_x_ui`, Persian default UI, offline-friendly install/update
   for servers in Iran (no GitHub/Google access from the server).
5. **Backups stay interchangeable with upstream 3x-ui**: same DB file name
   `x-ui.db`, same tables. Only additive changes listed here are allowed.

## Fixed decisions
- Names: service `jasem_x_ui`, CLI menu `jasem-x-ui`, install dir
  `/usr/local/jasem_x_ui/`, data dir `/etc/jasem_x_ui/` (DB stays `x-ui.db`),
  log dir `/var/log/jasem_x_ui/`. Panel binary file name stays `x-ui`
  inside the install dir. UI title `jasem_x_ui`.
- GitHub repo: `jasemhooti/jasem_x_ui` (public). Release assets:
  `jasem_x_ui-linux-amd64.tar.gz`, `jasem_x_ui-linux-arm64.tar.gz`, each
  containing panel + `bin/xray-linux-<arch>` (v26.6.27) +
  `bin/sing-box-linux-<arch>` (v1.14.2) + geo files + bundled `acme.sh`.
- Domain is optional, exactly like upstream (IP-only with Let's Encrypt
  shortlived IP cert must keep working).
- Only allowed schema change: `OutboundSubscription.Fragment bool`
  (`gorm:"default:false"`, json `fragment`). Nothing else in the DB.

## Shared interfaces (already stubbed on branch `jasem` — keep signatures)
- `internal/jasem/hooks.go` `PostProcessXrayConfig(cfg *xray.Config) error`
  — called at the end of `XrayService.GetXrayConfig`. Order:
  `fragment.Ensure` → `singbox.Bridge` → `compat.Apply`. Lead owns this file.
- `internal/singbox` `Protocol = "singbox"`, `IsSingboxOutbound(raw []byte) bool`,
  `ValidateOutbound(raw []byte) error`, `Bridge(cfg *xray.Config) error`.
  Already called from `CheckXrayConfig` (xray_setting.go) and
  `filterOutboundsRejectedByCore` (outbound_subscription.go).
- **sing-box pseudo-outbound shape** (produced by parsers, consumed by Bridge,
  shown by the UI):
  ```json
  {"tag":"<tag>","protocol":"singbox",
   "settings":{"outbound":{ <a sing-box outbound object, no "tag" key> }}}
  ```
  Use it ONLY for protocols xray-core v26.6.27 cannot dial: tuic, hysteria
  (v1), anytls, shadowtls, naive, ssh. Everything xray supports stays a native
  xray outbound.
- `internal/jasem/fragment` `Tag = "jasem-fragment"`, `Ensure(cfg)`. An
  outbound opts in by setting `streamSettings.sockopt.dialerProxy` to `Tag`.
- `internal/jasem/compat` `DefaultCoreVersion = "26.6.27"`, `Apply(cfg)`.
- Subscription skipped-line reasons: API field `skipped` on each
  subscription in list/preview responses: `[{ "line": "<first 80 chars>",
  "reason": "<short english>" }]`, kept in memory (not in DB).

## Work packages and file ownership
Each agent works ONLY in its own git worktree/branch and only on files it
owns. Shared files marked (lead) are edited by the lead at merge time.

### A — core compat (`feat/compat`)
Owns: `internal/jasem/compat/**`, `internal/xray/process.go` (only if needed
for version detection), tests in those dirs.
- Diff xray-core config parsing (`infra/conf`) between v26.6.27 and v26.9.9
  and list every key/shape 3.8.5 emits that 26.6.27 rejects or ignores
  (e.g. finalmask `udphop` vs `udpHop`, XMC `profiles`, xhttp sessionID
  keys, freedom/DNS changes). Also check what the 3.8.x DB migrations wrote.
- `Apply` detects the running core version (process or `xray version` on the
  binary, cached) and, only for versions < 26.9.9, rewrites the generated
  config to the old shape. Features with no old equivalent: drop that one
  outbound/inbound piece and `logger.Warning` it — never fail the whole config.
- Unit tests with table-driven before/after JSON.

### B — packaging, branding, install (`feat/packaging`)
Owns: `.github/workflows/release.yml` (other workflows: disable the ones
that need secrets or upstream infra), `install.sh`, `update.sh`, `x-ui.sh`
(→ installed as `jasem-x-ui`), `x-ui.service.*`, `Dockerfile`,
`DockerInit.sh`, `docker-compose.yml`, `internal/config/config.go`,
`internal/web/service/panel/panel.go` (self-update source), README.md.
- Paths/names per "Fixed decisions"; pin Xray v26.6.27 and bundle sing-box
  v1.14.2 in release archives (amd64 + arm64 Linux only is enough).
- Install/update must work offline: `install.sh --local <tar.gz>` and
  `jasem-x-ui update --local <tar.gz>`; plus optional `--mirror <base-url>`.
  acme.sh is bundled, not curl'ed from GitHub.
- Self-update in the panel points to `jasemhooti/jasem_x_ui`.
- Keep upstream SSL flows (domain + IP shortlived cert) working.

### C — parsers + subscription backend (`feat/parser`)
Owns: `internal/util/link/**`, `internal/web/service/outbound_subscription.go`
(except the singbox validation lines already present),
`internal/web/job/outbound_subscription_job.go`,
`internal/database/model/model.go` (only the `Fragment` field),
`internal/web/controller/` subscription handlers,
`frontend/src/lib/xray/outbound-link-parser.ts` + its tests.
- Case-insensitive schemes; add `socks://`, `http(s)://` proxy links,
  `tuic://`, `hysteria://`, `anytls://` (+ others in the sing-box list →
  sing-box pseudo-outbound shape above).
- Subscription bodies: base64/plain (existing), Clash YAML (`proxies:`),
  sing-box JSON (`outbounds:`), Xray JSON (single config or array of configs
  → take proxy outbounds). Prefer an existing yaml dep in go.mod.
- Return skipped lines + reasons (`skipped` field contract above).
- `Fragment` on a subscription → set `streamSettings.sockopt.dialerProxy`
  = `fragment.Tag` on each of its xray outbounds at merge time.
- Keep `FuzzParseLink` green; add golden tests for each new scheme/format.

### D — sing-box sidecar (`feat/singbox`)
Owns: `internal/singbox/**` (new), plus the start/stop wiring lines in the
xray lifecycle (`internal/web/service/xray.go` restart/stop paths only —
keep the diff tiny).
- Mirror `internal/tuic` (manager, process, orphans) for supervision.
- `Bridge`: for each `singbox` outbound allocate a stable loopback port
  (range 21000–21999, stable per tag), emit sing-box config with a `mixed`
  inbound per port routed to its outbound, replace the xray outbound with
  `{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":P}]}}`
  keeping the tag. Restart sidecar only when its config changes.
  No singbox outbounds → sidecar stopped.
- Binary: `<XUI_BIN_FOLDER>/sing-box-linux-<arch>`; missing binary → warn
  and drop those outbounds, never break xray.
- `ValidateOutbound`: structural checks (type, server, server_port).

### E — frontend (`feat/frontend`)
Owns: `frontend/src/**` except the link parser (C), `internal/web/translation/*.json`.
- Default UI language `fa-IR` for new sessions (fallback for missing keys
  stays en-US). Title/brand `jasem_x_ui`.
- Outbound list/form: accept protocol `singbox` (show the inner `type` as the
  protocol name, edit via JSON tab only).
- Outbound form: "Fragment" switch → sets/clears
  `streamSettings.sockopt.dialerProxy = "jasem-fragment"`.
- Subscription outbounds UI: `fragment` switch; show `skipped` list
  (count + expandable reasons).
- Lead also implements `fragment.Ensure` (tiny), not E.

## Done criteria per agent
- Code builds; your package tests pass (`go test ./<your pkgs>/...`;
  frontend: `npm run typecheck` + relevant vitest files).
- Commit on your branch with conventional commits. Do not merge, push or
  touch other branches.
- Final report ≤ 150 words: what changed, tests run, open issues,
  "Requests to lead".

## Environment notes (Windows dev box, network in Iran)
- Go: `C:\Users\jasemhooti\sdk\go\bin` (add to PATH). GOPROXY is set to
  goproxy.cn; Google hosts are blocked — never use proxy.golang.org.
- CGo SQLite needs gcc (WinLibs, on PATH via winget links).
- Network is flaky: retry downloads; do not loop more than 5 times.
- Keep token use low: read only the files you need, grep before reading.
