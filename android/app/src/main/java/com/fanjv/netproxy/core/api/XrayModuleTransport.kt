package com.fanjv.netproxy.core.api

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * Transport for the Xray based NetProxy module.
 *
 * The manager's repositories and view models were written against an HTTPS API served by the module.
 * The Xray module is script based, so this transport answers the very same requests by running the
 * module's own scripts through root and returns the same `schema = 1` JSON envelope.
 */
internal class XrayModuleTransport(context: Context) : ModuleApiTransport {
    private val backend = XrayBackend(context.applicationContext)

    override suspend fun reconnect(address: String) = Unit

    override suspend fun <T> request(
        method: String,
        path: String,
        body: JsonObject?,
        query: Map<String, String>,
        mutation: Boolean,
        decode: (Int, InputStream) -> T,
    ): T {
        val (status, payload) = try {
            200 to envelope(true, "ok", "", backend.handle(method, path, body ?: JsonObject(emptyMap()), query))
        } catch (error: CancellationException) {
            throw error
        } catch (error: ModuleApiException) {
            400 to envelope(false, error.resultCode, error.message, error.data)
        } catch (error: Exception) {
            500 to envelope(false, "api.internal", error.message ?: error.javaClass.simpleName, JsonObject(emptyMap()))
        }
        return decode(status, ByteArrayInputStream(payload.toByteArray(Charsets.UTF_8)))
    }

    override suspend fun download(path: String, query: Map<String, String>, destination: File) =
        backend.download(path, destination)

    override suspend fun image(path: String): ByteArray = backend.image(path)

    override suspend fun watch(topics: Set<String>, consume: suspend (ModuleEvent) -> Unit) = backend.watch(topics, consume)
}

internal fun envelope(ok: Boolean, code: String, message: String, data: JsonElement): String = buildJsonObject {
    put("schema", 1)
    put("ok", ok)
    put("code", code)
    put("message", message)
    put("data", data)
}.toString()

private class XrayStatus(
    val pid: Int?,
    val startMillis: Long,
    val rssKb: Long,
    val cpuTicks: Long,
    val sysTicks: Long,
    val conf: Map<String, String>,
) {
    val running: Boolean get() = pid != null
}

private val outboundModes = listOf("rule", "global", "direct")
private val packageToken = Regex("[A-Za-z0-9_.:]+")

internal class XrayBackend(context: Context) {
    private val json = Json { ignoreUnknownKeys = true }
    private val catalog = XrayCatalog()
    private val apps = XrayAndroidApps(context)
    private val firstSeen = ConcurrentHashMap<Int, Long>()
    private val delays = ConcurrentHashMap<String, Pair<Int, Long>>()

    suspend fun handle(method: String, path: String, body: JsonObject, query: Map<String, String>): JsonElement {
        val seg = path.trim('/').split('/')
        return when {
            path == "/info" -> info()
            path == "/service" && method == "GET" -> statusData(status())
            path == "/service/check" -> JsonObject(emptyMap())
            seg[0] == "service" && seg.size == 2 && method == "POST" -> serviceAction(seg[1])
            path == "/mode" && method == "PUT" -> setMode(body.text("mode"))
            seg[0] == "subscriptions" -> catalog.subscriptions(method, seg, body, query)
            seg[0] == "nodes" -> catalog.nodes(method, seg, body, query)
            seg[0] == "policy-groups" -> policyGroups(method, seg, body, query)
            path == "/configs" -> JsonArray(emptyList())
            path == "/config/validate" -> JsonObject(emptyMap())
            seg[0] == "config" -> config(method, body, query)
            path == "/logs" -> logs(method, query)
            path == "/network/wifi-list" -> buildJsonObject { put("ssids", JsonArray(emptyList())) }
            path == "/diagnostics/ebpf" -> fail("api.unsupported", "eBPF diagnostics are not available in the Xray module")
            path == "/android/apps" -> apps.snapshot()
            else -> fail("api.not_found", "Unsupported request: $method $path")
        }
    }

    // ---- service ------------------------------------------------------------------------

    private suspend fun info(): JsonElement {
        val result = RootShell.exec("test -d ${shQuote("$MODULE_DIR/scripts")}")
        if (!result.ok) fail("api.connection_unavailable", "The NetProxy module is not installed")
        return buildJsonObject { put("name", "NetProxy"); put("backend", "xray") }
    }

    private suspend fun status(): XrayStatus {
        val script = listOf(
            "pid=\$(pidof -s ${shQuote(XRAY_BIN)} 2>/dev/null)",
            "echo pid=\$pid",
            "if [ -n \"\$pid\" ]; then",
            "  echo start=\$(stat -c %Y /proc/\$pid 2>/dev/null)",
            "  echo rss=\$(awk '/VmRSS/{print \$2}' /proc/\$pid/status 2>/dev/null)",
            "  echo cpu=\$(awk '{print \$14+\$15}' /proc/\$pid/stat 2>/dev/null)",
            "fi",
            "echo sys=\$(awk '/^cpu /{s=0;for(i=2;i<=NF;i++)s+=\$i;print s}' /proc/stat 2>/dev/null)",
            "echo ---conf",
            "cat ${shQuote(MODULE_CONF)} 2>/dev/null",
        ).joinToString("\n")
        val result = RootShell.exec(script)
        if (!result.ok && result.out.isBlank()) fail("api.connection_unavailable", result.message().ifEmpty { "Cannot query the module" })
        val parts = result.out.split("---conf", limit = 2)
        val values = parts[0].lines().filter { it.contains('=') }
            .associate { it.substringBefore('=') to it.substringAfter('=').trim() }
        val pid = values["pid"]?.toIntOrNull()
        var start = (values["start"]?.toLongOrNull() ?: 0L) * 1000
        if (pid != null && start <= 0) start = firstSeen.getOrPut(pid) { System.currentTimeMillis() }
        return XrayStatus(
            pid = pid,
            startMillis = start,
            rssKb = values["rss"]?.toLongOrNull() ?: 0L,
            cpuTicks = values["cpu"]?.toLongOrNull() ?: 0L,
            sysTicks = values["sys"]?.toLongOrNull() ?: 0L,
            conf = parseConf(parts.getOrElse(1) { "" }),
        )
    }

    private fun statusData(st: XrayStatus): JsonObject {
        val mode = st.conf["OUTBOUND_MODE"].orEmpty().ifEmpty { "rule" }
        val now = System.currentTimeMillis()
        return buildJsonObject {
            put("state", if (st.running) "ready" else "stopped")
            put("pid", st.pid)
            put("started_at", st.startMillis / 1000)
            put("core_started_at_millis", st.startMillis)
            put("ready_at", st.startMillis / 1000)
            put("uptime_seconds", if (st.running && st.startMillis > 0) ((now - st.startMillis) / 1000).coerceAtLeast(0) else 0L)
            put("error", "")
            put("outbound_mode", mode)
            put("configured_outbound_mode", mode)
            put("available_outbound_modes", JsonArray(outboundModes.map { JsonPrimitive(it) }))
            put("configured_backend", "xray")
            put("active_backend", if (st.running) "xray" else null as String?)
            put("memory_bytes", st.rssKb * 1024)
            put("process_cpu_ticks", st.cpuTicks)
            put("system_cpu_ticks", st.sysTicks)
            put("cpu_count", Runtime.getRuntime().availableProcessors())
            put("worker_state", if (st.running) "running" else "stopped")
            put("worker_pid", st.pid)
        }
    }

    private fun trafficData(st: XrayStatus): JsonObject = buildJsonObject {
        put("available", st.running)
        if (st.running) {
            put("started_at_millis", st.startMillis)
            put("status", buildJsonObject {
                put("memory", st.rssKb * 1024)
                put("connections_in", 0)
                put("connections_out", 0)
                put("uplink_total", 0L)
                put("downlink_total", 0L)
            })
            put("process_cpu_ticks", st.cpuTicks)
            put("system_cpu_ticks", st.sysTicks)
            put("cpu_count", Runtime.getRuntime().availableProcessors())
        }
    }

    private suspend fun serviceAction(action: String): JsonElement {
        val command = when (action) {
            "start", "stop", "restart" -> "sh ${shQuote(CLI)} $action"
            "reload" -> "sh ${shQuote(CLI)} proxy reload"
            else -> fail("api.not_found", "Unknown service action: $action")
        }
        val result = RootShell.exec(command)
        if (!result.ok) fail("service.$action", result.message().ifEmpty { "Service $action failed" })
        return JsonObject(emptyMap())
    }

    private suspend fun setMode(mode: String): JsonElement {
        if (mode !in outboundModes) fail("api.invalid_request", "Unknown outbound mode: $mode")
        val result = RootShell.exec("sh ${shQuote("$MODULE_DIR/scripts/core/switch-mode.sh")} ${shQuote(mode)}")
        if (!result.ok || result.out.contains("error")) fail("service.mode", result.message().ifEmpty { "Could not switch mode" })
        return JsonObject(emptyMap())
    }

    // ---- node selection (policy groups) -------------------------------------------------

    private fun currentTag(conf: Map<String, String>): String {
        val path = conf["CURRENT_CONFIG"].orEmpty()
        return if (path.startsWith("$OUTBOUNDS_DIR/")) path.removePrefix("$OUTBOUNDS_DIR/").removeSuffix(".json") else ""
    }

    /**
     * Xray has no selector groups. The manager's proxy page is fed one synthetic selector whose members are
     * every node file, and selecting a member switches the module's active config.
     */
    private suspend fun policySnapshot(st: XrayStatus, configOnly: Boolean): JsonObject {
        val groups = catalog.scan()
        val current = currentTag(st.conf)
        val items = groups.flatMap { group ->
            group.nodes.map { node ->
                val tag = "${group.id}/${node.tag}"
                val delay = delays[tag]
                buildJsonObject {
                    put("tag", tag)
                    put("type", node.protocol.ifEmpty { "outbound" })
                    put("url_test_delay", delay?.first ?: 0)
                    put("url_test_time", delay?.second ?: 0L)
                    put("display_name", if (group.isLocal) node.tag else "${node.tag} · ${group.name}")
                }
            }
        }
        val selector = buildJsonObject {
            put("tag", "proxy")
            put("type", "selector")
            put("selectable", !configOnly)
            put("items", JsonArray(items))
            put("selected", current)
            put("configured_default", current)
        }
        return buildJsonObject {
            put("groups", JsonArray(listOf(selector)))
            put("live", !configOnly)
            // The manager needs a positive identity to allow switching; use the real start time while running.
            put("core_started_at_millis", if (configOnly) 0L else if (st.running) st.startMillis else 1L)
        }
    }

    private suspend fun policyGroups(method: String, seg: List<String>, body: JsonObject, query: Map<String, String>): JsonElement {
        val st = status()
        if (seg.size == 1 && method == "GET") return policySnapshot(st, query["source"] == "config")
        if (seg.size == 2 && method == "POST" && seg[1] == "select") {
            val member = body.text("member_tag")
            val group = member.substringBefore('/', "")
            val file = member.substringAfter('/', "")
            val path = nodeFilePath(group, file)
            val script = buildString {
                appendLine("[ -f ${shQuote(path)} ] || { echo 'Node not found' >&2; exit 1; }")
                if (st.running) {
                    appendLine("sh ${shQuote("$MODULE_DIR/scripts/core/switch-config.sh")} ${shQuote(path)}")
                } else {
                    appendLine(". ${shQuote(COMMON_SH)} && conf_set ${shQuote(MODULE_CONF)} CURRENT_CONFIG ${shQuote("\"$path\"")}")
                }
            }
            val result = RootShell.exec(script)
            if (!result.ok) fail("node.select", result.message().ifEmpty { "Could not switch node" })
            return policySnapshot(status(), false)
        }
        if (seg.size == 2 && method == "POST" && seg[1] == "delay") {
            measureDelays()
            return JsonObject(emptyMap())
        }
        fail("api.not_found", "Unsupported request")
    }

    /** Measures TCP connect time to each node's server. UDP-only nodes (WireGuard) report no value. */
    private suspend fun measureDelays() {
        val groups = catalog.scanWithContent()
        val targets = groups.flatMap { group -> group.nodes.map { node -> "${group.id}/${node.tag}" to catalog.nodeInfo(node) } }
        val limit = Semaphore(16)
        coroutineScope {
            targets.map { (tag, info) ->
                async(Dispatchers.IO) {
                    limit.withPermit {
                        val host = info.text("server")
                        val port = (info["port"] as? JsonPrimitive)?.intOrNull ?: 0
                        val ms = if (host.isEmpty() || port <= 0) 0 else tcpDelay(host, port)
                        delays[tag] = ms to System.currentTimeMillis()
                    }
                }
            }.awaitAll()
        }
    }

    private fun tcpDelay(host: String, port: Int): Int = try {
        Socket().use { socket ->
            val begin = System.nanoTime()
            socket.connect(InetSocketAddress(host, port), 3_000)
            ((System.nanoTime() - begin) / 1_000_000).toInt().coerceAtLeast(1)
        }
    } catch (_: Exception) {
        0
    }

    // ---- configuration targets ----------------------------------------------------------

    private class AppPolicy(val enabled: Boolean, val mode: String, val proxy: List<String>, val bypass: List<String>) {
        val revision: String get() = Integer.toHexString("$enabled|$mode|${proxy.joinToString(" ")}|${bypass.joinToString(" ")}".hashCode())
        fun toContent(): String = buildJsonObject {
            put("app", buildJsonObject {
                put("enabled", enabled)
                put("mode", mode)
                put("proxy_apps", JsonArray(proxy.map { JsonPrimitive(it) }))
                put("bypass_apps", JsonArray(bypass.map { JsonPrimitive(it) }))
            })
        }.toString()
    }

    private suspend fun readConf(path: String): Map<String, String> {
        val result = RootShell.exec("cat ${shQuote(path)}")
        if (!result.ok) fail("config.read", result.message().ifEmpty { "Cannot read the module configuration" })
        return parseConf(result.out)
    }

    private suspend fun readAppPolicy(): AppPolicy {
        val conf = readConf(TPROXY_CONF)
        fun list(key: String) = conf[key].orEmpty().split(Regex("\\s+")).filter(String::isNotEmpty)
        return AppPolicy(
            enabled = conf["APP_PROXY_ENABLE"] == "1",
            mode = conf["APP_PROXY_MODE"].orEmpty().ifEmpty { "blacklist" },
            proxy = list("PROXY_APPS_LIST"),
            bypass = list("BYPASS_APPS_LIST"),
        )
    }

    private fun snapshot(content: String, revision: String) = buildJsonObject {
        put("content", content)
        put("revision", revision)
    }

    private suspend fun config(method: String, body: JsonObject, query: Map<String, String>): JsonElement {
        val target = query["target"].orEmpty()
        return when (method) {
            "GET" -> when (target) {
                "inbound/app" -> readAppPolicy().let { snapshot(it.toContent(), it.revision) }
                "module/auto_start" -> {
                    val enabled = readConf(MODULE_CONF)["AUTO_START"] == "1"
                    snapshot("""{"auto_start":$enabled}""", enabled.toString())
                }
                "module/wifi" -> snapshot(
                    """{"wifi":{"enabled":false,"mode":"blacklist","blacklist":[],"whitelist":[],"proxy_on_non_wifi":true}}""", "0",
                )
                else -> fail("api.unsupported", "'$target' is not available in the Xray module")
            }
            "PUT" -> when (target) {
                "inbound/app" -> writeAppPolicy(body)
                "module/auto_start" -> writeAutoStart(body)
                else -> fail("api.unsupported", "'$target' cannot be changed in the Xray module")
            }
            else -> fail("api.method_not_allowed", "Unsupported method")
        }
    }

    private suspend fun writeAppPolicy(body: JsonObject): JsonElement {
        val current = readAppPolicy()
        if (body.text("revision") != current.revision) fail("config.conflict", "The app list was changed elsewhere. Reload and try again")
        val app = (runCatching { json.parseToJsonElement(body.text("content")) as? JsonObject }.getOrNull()
            ?.get("app") as? JsonObject) ?: fail("config.apply", "Invalid app policy")
        val enabled = (app["enabled"] as? JsonPrimitive)?.booleanOrNull ?: fail("config.apply", "Invalid app policy")
        val mode = app.text("mode")
        if (mode != "blacklist" && mode != "whitelist") fail("config.apply", "Invalid proxy mode")
        fun list(key: String): List<String> = (app[key] as? JsonArray).orEmpty().map { element ->
            (element as? JsonPrimitive)?.content.orEmpty().also {
                if (!packageToken.matches(it)) fail("config.apply", "Invalid package name: $it")
            }
        }.distinct()
        val updated = AppPolicy(enabled, mode, list("proxy_apps"), list("bypass_apps"))
        val script = buildString {
            appendLine(". ${shQuote(COMMON_SH)}")
            appendLine("conf_set ${shQuote(TPROXY_CONF)} APP_PROXY_ENABLE ${if (enabled) 1 else 0}")
            appendLine("conf_set ${shQuote(TPROXY_CONF)} APP_PROXY_MODE ${shQuote("\"$mode\"")}")
            appendLine("conf_set ${shQuote(TPROXY_CONF)} PROXY_APPS_LIST ${shQuote("\"${updated.proxy.joinToString(" ")}\"")}")
            appendLine("conf_set ${shQuote(TPROXY_CONF)} BYPASS_APPS_LIST ${shQuote("\"${updated.bypass.joinToString(" ")}\"")}")
            appendLine("if pidof -s ${shQuote(XRAY_BIN)} >/dev/null 2>&1; then sh ${shQuote(CLI)} proxy reload; fi")
        }
        val result = RootShell.exec(script)
        if (!result.ok) fail("config.apply", result.message().ifEmpty { "Could not apply the app policy" })
        return buildJsonObject { put("revision", updated.revision) }
    }

    private suspend fun writeAutoStart(body: JsonObject): JsonElement {
        val enabled = (runCatching { json.parseToJsonElement(body.text("content")) as? JsonObject }.getOrNull()
            ?.get("auto_start") as? JsonPrimitive)?.booleanOrNull ?: fail("config.apply", "Invalid auto-start setting")
        val script = ". ${shQuote(COMMON_SH)} && conf_set ${shQuote(MODULE_CONF)} AUTO_START ${if (enabled) 1 else 0}"
        val result = RootShell.exec(script)
        if (!result.ok) fail("config.apply", result.message().ifEmpty { "Could not save the setting" })
        return buildJsonObject { put("revision", enabled.toString()) }
    }

    // ---- logs and diagnostics -----------------------------------------------------------

    private val serviceLine = Regex("""^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})]\s+\[([A-Za-z]+)]\s*(.*)$""")

    private suspend fun logs(method: String, query: Map<String, String>): JsonElement {
        val core = query["kind"] == "core"
        val file = "$MODULE_DIR/logs/${if (core) "xray.log" else "service.log"}"
        if (method == "DELETE") {
            RootShell.exec(": > ${shQuote(file)}")
            return JsonObject(emptyMap())
        }
        val lines = query["lines"]?.toIntOrNull()?.coerceIn(1, 5000) ?: 800
        val text = RootShell.exec("tail -n $lines ${shQuote(file)} 2>/dev/null").out
        if (core) return buildJsonObject { put("content", text) }
        var lastTimestamp = ""
        val entries = text.lineSequence().filter(String::isNotBlank).map { raw ->
            val match = serviceLine.matchEntire(raw.trim())
            val timestamp = match?.groupValues?.get(1) ?: lastTimestamp
            lastTimestamp = timestamp
            val level = match?.groupValues?.get(2)?.uppercase()?.let { if (it == "WARNING") "WARN" else it } ?: "INFO"
            buildJsonObject {
                put("timestamp", timestamp)
                put("level", level)
                put("component", "module")
                put("event", "log")
                put("result", if (level == "ERROR") "failed" else "ok")
                put("error_code", "")
                put("message", match?.groupValues?.get(3) ?: raw.trim())
            }
        }.toList()
        return buildJsonObject { put("entries", JsonArray(entries)) }
    }

    /** Streams a redacted tarball of the module logs into [destination]. */
    suspend fun download(path: String, destination: File) {
        if (path != "/diagnostics/export") fail("api.download_failed", "Unsupported download")
        val redact = "s#(https?|vless|vmess|trojan|ss|socks5?|wireguard|wg|hysteria2|hy2)://[^ \"]+#\\1://<redacted>#g"
        val script = listOf(
            "d=/data/local/tmp/netproxy_diag_\$\$",
            "rm -rf \"\$d\"; mkdir -p \"\$d\" || exit 1",
            "for f in ${shQuote("$MODULE_DIR/logs")}/*.log; do [ -f \"\$f\" ] && sed -E ${shQuote(redact)} \"\$f\" > \"\$d/\${f##*/}\"; done",
            "{ echo \"xray: \$(${shQuote(XRAY_BIN)} version 2>/dev/null | head -n 1)\";",
            "  grep -E '^(id|version|versionCode)=' ${shQuote("$MODULE_DIR/module.prop")};",
            "  grep -E '^(OUTBOUND_MODE|AUTO_START)=' ${shQuote(MODULE_CONF)}; } > \"\$d/info.txt\" 2>/dev/null",
            "tar -czf - -C \"\$d\" .",
            "rc=\$?; rm -rf \"\$d\"; exit \$rc",
        ).joinToString("\n")
        RootShell.execToFile(script, destination)
    }

    suspend fun image(path: String): ByteArray = apps.icon(path.removePrefix("/android/icons/"))

    // ---- events -------------------------------------------------------------------------

    /** The manager expects pushed events; the script based module is polled instead. */
    suspend fun watch(topics: Set<String>, consume: suspend (ModuleEvent) -> Unit) {
        while (currentCoroutineContext().isActive) {
            val st = status()
            if ("status" in topics) {
                consume(ModuleEvent("status", envelope(true, "ok", "", statusData(st))))
                consume(ModuleEvent("traffic", envelope(true, "ok", "", trafficData(st))))
            }
            if ("groups" in topics) consume(ModuleEvent("groups", envelope(true, "ok", "", policySnapshot(st, false))))
            if ("subscriptions" in topics) {
                consume(ModuleEvent("subscriptions", envelope(true, "ok", "", JsonArray(catalog.scan().map { catalog.summary(it) }))))
            }
            delay(3_000)
        }
    }
}
