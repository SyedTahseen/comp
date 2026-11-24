# NetProxy Manager – Xray module port

The manager was written for the sing-box module, which exposed a pinned local HTTPS/SSE API
(served by a Go worker). The Xray module is script based and has no such server, so the transport
layer was replaced; repositories, view models and screens are unchanged except where noted.

## How it works
`core/api/XrayModuleTransport.kt` implements `ModuleApiTransport` and answers every request by running
the module's own scripts through `su`, returning the same `schema = 1` JSON envelope.

| Manager call | Xray module implementation |
|---|---|
| `/service`, events `status`/`traffic` | `pidof xray`, `/proc`, `module.conf` (polled every 3 s) |
| `/service/{start,stop,restart,reload}` | `scripts/cli start|stop|restart`, `cli proxy reload` |
| `/mode` | `scripts/core/switch-mode.sh rule|global|direct` |
| `/subscriptions…` | `outbounds/sub_*/_meta.json`, `cli sub add|update|update-all|remove` |
| `/nodes…` | `outbounds/<group>/<node>.json`, `cli config add` (links, `wireguard://`, wg-quick `.conf`) |
| `/policy-groups…` | one synthetic selector; selecting runs the module's config hot-switch |
| `/config?target=inbound/app` | `tproxy.conf` (APP_PROXY_*, PROXY_APPS_LIST, BYPASS_APPS_LIST) |
| `/config?target=module/auto_start` | `module.conf` AUTO_START |
| `/logs`, `/diagnostics/export` | `logs/service.log`, `logs/xray.log`; export is a URL-redacted tar.gz |
| `/android/apps`, `/android/icons/*` | local `PackageManager` (needs `QUERY_ALL_PACKAGES`) |

Files: `RootShell.kt`, `XrayModuleTransport.kt`, `XrayCatalog.kt`, `XrayAndroidApps.kt`.

## UI changes
- Settings → Proxy now only contains **Per-app proxy** (inbound/eBPF, Wi-Fi matching, rule sets and the
  sing-box JSON editor have no Xray equivalent).
- Proxy page: policy-group management removed (sing-box `outbounds`). Latency test = TCP connect time.
- Reconnect dialog no longer asks for a local HTTPS address.
- `build.gradle.kts`: removed the test input that pointed at `module/config/singbox/config.json`.

## Not available with Xray
Node share-link export, subscription auto-update schedule/headers/filters (module stores name + URL only),
traffic totals and connection counts (Xray stats are disabled in `05_policy.json`), Wi-Fi policy,
multi-user app lists (user 0 only).

## Notes
- Unit tests for the sing-box schema/kernel editor target removed functionality and are expected to fail.
- Build: Android Studio / `./gradlew assembleDebug` (needs network once for the MIUIX checkout, see settings.gradle.kts).
- Same `applicationId` as upstream: uninstall the old manager first if signatures differ.
