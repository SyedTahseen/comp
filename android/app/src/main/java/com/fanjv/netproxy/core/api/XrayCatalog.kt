package com.fanjv.netproxy.core.api

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put

internal fun fail(code: String, message: String): Nothing = throw ModuleApiException(code, message)

internal fun JsonObject.text(key: String): String = (this[key] as? JsonPrimitive)?.contentOrNull.orEmpty()

internal const val DEFAULT_GROUP = "default"
internal const val SUB_PREFIX = "sub_"

internal class NodeScan(val file: String) {
    val tag: String get() = file.removeSuffix(".json")
    var content: String = ""
    var protocol: String = ""
}

internal class GroupScan(val id: String) {
    var meta: JsonObject? = null
    val nodes = ArrayList<NodeScan>()
    val isLocal: Boolean get() = id == DEFAULT_GROUP
    val name: String get() = if (isLocal) "Local" else meta?.text("name").orEmpty().ifEmpty { id.removePrefix(SUB_PREFIX) }
    val updated: String get() = meta?.text("updated").orEmpty()
}

/** `sub add` stores subscriptions under `sub_<name>` with these characters replaced. */
internal fun sanitizeName(name: String): String = name.replace(Regex("[/\\\\:*?\"<>| ]"), "_")

private fun requireSafeSegment(value: String, what: String): String {
    if (value.isEmpty() || value == "." || value.contains("..") || value.contains('/') || value.contains('\\') ||
        value.startsWith("-") || value.any { it == '\n' || it == '\r' || it == '\u0000' }
    ) fail("api.invalid_request", "Invalid $what")
    return value
}

/** Rejects text that cannot be stored in the module's hand-written `_meta.json`. */
private fun requireMetaSafe(value: String, what: String): String {
    if (value.isBlank() || value.any { it == '"' || it == '\\' || it == '\n' || it == '\r' }) {
        fail("api.invalid_request", "$what must not be empty or contain quotes, backslashes or line breaks")
    }
    return value
}

internal fun nodeFilePath(group: String, tag: String): String =
    "$OUTBOUNDS_DIR/${requireSafeSegment(group, "group")}/${requireSafeSegment(tag, "node")}.json"

/** Reads and mutates the module's outbound catalog: `default/` plus one `sub_*` directory per subscription. */
internal class XrayCatalog {
    private val json = Json { ignoreUnknownKeys = true }

    // ---- scanning -----------------------------------------------------------------------

    private fun scanScript(withContent: Boolean) = buildString {
        appendLine("cd ${shQuote(OUTBOUNDS_DIR)} 2>/dev/null || exit 0")
        appendLine("for d in default sub_*; do")
        appendLine("  [ -d \"\$d\" ] || continue")
        appendLine("  echo \"@@G \$d\"")
        appendLine("  if [ -f \"\$d/_meta.json\" ]; then echo '@@M'; cat \"\$d/_meta.json\"; echo; fi")
        appendLine("  for f in \"\$d\"/*.json; do")
        appendLine("    [ -f \"\$f\" ] || continue")
        appendLine("    b=\${f##*/}")
        appendLine("    [ \"\$b\" = \"_meta.json\" ] && continue")
        appendLine("    echo \"@@N \$b\"")
        if (withContent) appendLine("    cat \"\$f\"; echo")
        appendLine("  done")
        if (!withContent) {
            appendLine("  grep -H -m1 -o '\"protocol\": *\"[a-z0-9]*\"' \"\$d\"/*.json 2>/dev/null | sed 's/^/@@P /'")
        }
        appendLine("done")
    }

    suspend fun scan(withContent: Boolean = false): List<GroupScan> {
        val result = RootShell.exec(scanScript(withContent))
        if (!result.ok && result.out.isEmpty()) fail("catalog.read", result.message().ifEmpty { "Cannot read the node catalog" })
        return parseScan(result.out)
    }

    private fun parseScan(text: String): List<GroupScan> {
        val groups = ArrayList<GroupScan>()
        var group: GroupScan? = null
        var node: NodeScan? = null
        var mode = 0 // 0 = none, 1 = meta json, 2 = node content
        val buffer = StringBuilder()

        fun flush() {
            when (mode) {
                1 -> group?.meta = runCatching { json.parseToJsonElement(buffer.toString()) as? JsonObject }.getOrNull()
                2 -> node?.content = buffer.toString().trim()
            }
            buffer.setLength(0)
            mode = 0
        }

        for (line in text.lineSequence()) {
            when {
                line.startsWith("@@G ") -> {
                    flush()
                    group = GroupScan(line.substring(4).trim()).also { groups.add(it) }
                    node = null
                }
                line == "@@M" -> { flush(); mode = 1 }
                line.startsWith("@@N ") -> {
                    flush()
                    node = NodeScan(line.substring(4).trim()).also { group?.nodes?.add(it) }
                    mode = 2
                }
                line.startsWith("@@P ") -> {
                    flush()
                    val rest = line.substring(4)
                    val marker = rest.lastIndexOf(":\"protocol\"")
                    if (marker > 0) {
                        val file = rest.substring(0, marker).substringAfterLast('/')
                        val protocol = rest.trimEnd().removeSuffix("\"").substringAfterLast('"')
                        group?.nodes?.firstOrNull { it.file == file }?.protocol = protocol
                    }
                }
                else -> if (mode != 0) buffer.append(line).append('\n')
            }
        }
        flush()
        return groups
    }

    // ---- JSON shaping -------------------------------------------------------------------

    fun summary(group: GroupScan): JsonObject = buildJsonObject {
        put("id", group.id)
        put("name", group.name)
        put("type", if (group.isLocal) "local" else "subscription")
        put("node_count", group.nodes.size)
        put("revision", (group.nodes.joinToString("|") { it.file }.hashCode().toLong() and 0x7fffffffL))
        put("auto_update", false)
        put("update_interval", 86400)
        put("update_via_proxy", "auto")
        put("last_success_at", group.updated)
        put("updated_at", group.updated)
        put("runtime_tag", group.id)
    }

    /** Extracts protocol, server and port from an Xray outbound file. */
    fun nodeInfo(node: NodeScan): JsonObject {
        val root = runCatching { json.parseToJsonElement(node.content) as? JsonObject }.getOrNull()
        val outbound = (root?.get("outbounds") as? JsonArray)?.firstOrNull() as? JsonObject
        val settings = outbound?.get("settings") as? JsonObject
        var server = ""
        var port = 0

        fun fromEntry(entry: JsonObject?) {
            if (entry == null) return
            server = entry.text("address")
            port = (entry["port"] as? JsonPrimitive)?.intOrNull ?: 0
        }
        fromEntry((settings?.get("vnext") as? JsonArray)?.firstOrNull() as? JsonObject)
        if (server.isEmpty()) fromEntry((settings?.get("servers") as? JsonArray)?.firstOrNull() as? JsonObject)
        if (server.isEmpty()) fromEntry(settings)
        if (server.isEmpty()) {
            val endpoint = ((settings?.get("peers") as? JsonArray)?.firstOrNull() as? JsonObject)?.text("endpoint").orEmpty()
            server = endpoint.substringBeforeLast(':', endpoint).removeSurrounding("[", "]")
            port = endpoint.substringAfterLast(':', "").toIntOrNull() ?: 0
        }
        return buildJsonObject {
            put("tag", node.tag)
            put("protocol", outbound?.text("protocol").orEmpty().ifEmpty { node.protocol })
            put("server", server)
            put("port", port)
        }
    }

    private suspend fun detailsOf(id: String): GroupScan =
        scan(true).firstOrNull { it.id == id } ?: fail("subscription.not_found", "Group not found: $id")

    // ---- subscriptions ------------------------------------------------------------------

    suspend fun subscriptions(method: String, seg: List<String>, body: JsonObject, query: Map<String, String>): JsonElement {
        if (seg.size == 1) {
            return when (method) {
                "GET" -> JsonArray(scan().map { summary(it) })
                "POST" -> addSubscription(body)
                else -> fail("api.method_not_allowed", "Unsupported method")
            }
        }
        if (seg[1] == "update-all" && method == "POST") {
            val result = RootShell.exec("sh ${shQuote(CLI)} sub update-all", timeoutMs = 600_000)
            if (!result.ok) fail("subscription.update", result.message().ifEmpty { "Update failed" })
            return JsonObject(emptyMap())
        }
        val id = requireSafeSegment(seg[1], "group")
        if (seg.size == 3) {
            return when {
                seg[2] == "update" && method == "POST" -> updateSubscription(id)
                seg[2] == "history" && method == "GET" -> JsonArray(emptyList())
                else -> fail("api.not_found", "Unsupported request")
            }
        }
        return when (method) {
            "GET" -> if (query["private"] == "true") editorState(id) else details(id)
            "PUT" -> editSubscription(id, body)
            "DELETE" -> removeSubscription(id)
            else -> fail("api.method_not_allowed", "Unsupported method")
        }
    }

    private suspend fun details(id: String): JsonElement {
        val group = detailsOf(id)
        return buildJsonObject {
            put("group", summary(group))
            put("nodes", JsonArray(group.nodes.map { nodeInfo(it) }))
        }
    }

    private suspend fun editorState(id: String): JsonElement {
        val group = scan().firstOrNull { it.id == id } ?: fail("subscription.not_found", "Group not found: $id")
        val meta = group.meta ?: fail("subscription.edit", "This group is not a subscription")
        return buildJsonObject {
            put("id", id)
            put("name", meta.text("name"))
            put("url", meta.text("url"))
            put("auto_update", false)
            put("update_interval", 86400)
            put("update_via_proxy", "auto")
        }
    }

    private suspend fun addSubscription(body: JsonObject): JsonElement {
        val name = requireMetaSafe(body.text("name").trim(), "Name")
        val url = requireMetaSafe(body.text("url").trim(), "URL")
        val result = RootShell.exec("sh ${shQuote(CLI)} sub add ${shQuote(name)} ${shQuote(url)}", timeoutMs = 600_000)
        if (!result.ok) fail("subscription.add", result.message().ifEmpty { "Could not add the subscription" })
        val id = SUB_PREFIX + sanitizeName(name)
        return buildJsonObject { put("id", id); put("group_id", id) }
    }

    private suspend fun metaOf(id: String): JsonObject {
        val group = scan().firstOrNull { it.id == id } ?: fail("subscription.not_found", "Group not found: $id")
        return group.meta ?: fail("subscription.edit", "This group is not a subscription")
    }

    private suspend fun updateSubscription(id: String): JsonElement {
        val name = metaOf(id).text("name")
        val result = RootShell.exec("sh ${shQuote(CLI)} sub update ${shQuote(name)}", timeoutMs = 600_000)
        if (!result.ok) fail("subscription.update", result.message().ifEmpty { "Update failed" })
        return JsonObject(emptyMap())
    }

    /** The module only stores a name and URL per subscription; other editor fields are ignored. */
    private suspend fun editSubscription(id: String, body: JsonObject): JsonElement {
        val meta = metaOf(id)
        val name = requireMetaSafe(body.text("name").ifEmpty { meta.text("name") }.trim(), "Name")
        val url = requireMetaSafe(body.text("url").ifEmpty { meta.text("url") }.trim(), "URL")
        val newId = SUB_PREFIX + sanitizeName(name)
        val content = "{\n  \"name\": \"$name\",\n  \"url\": \"$url\",\n  \"updated\": \"${meta.text("updated")}\"\n}\n"
        val script = buildString {
            if (newId != id) {
                appendLine("[ -e ${shQuote("$OUTBOUNDS_DIR/$newId")} ] && { echo 'A subscription with this name already exists' >&2; exit 3; }")
                appendLine("mv ${shQuote("$OUTBOUNDS_DIR/$id")} ${shQuote("$OUTBOUNDS_DIR/$newId")} || exit 1")
            }
            appendLine("cat > ${shQuote("$OUTBOUNDS_DIR/$newId/_meta.json")}")
        }
        val result = RootShell.exec(script, stdin = content)
        if (!result.ok) fail("subscription.edit", result.message().ifEmpty { "Could not save the subscription" })
        return buildJsonObject { put("id", newId); put("group_id", newId) }
    }

    private suspend fun removeSubscription(id: String): JsonElement {
        val name = metaOf(id).text("name")
        val result = RootShell.exec("sh ${shQuote(CLI)} sub remove ${shQuote(name)}")
        if (!result.ok) fail("subscription.remove", result.message().ifEmpty { "Could not remove the subscription" })
        return JsonObject(emptyMap())
    }

    // ---- nodes --------------------------------------------------------------------------

    suspend fun nodes(method: String, seg: List<String>, body: JsonObject, query: Map<String, String>): JsonElement {
        if (seg.size == 1) {
            return when (method) {
                "POST" -> addNode(body.text("content"))
                "PUT" -> editNode(body)
                "DELETE" -> removeNode(query)
                else -> fail("api.method_not_allowed", "Unsupported method")
            }
        }
        return when (seg[1]) {
            "import" -> importNodes(body.text("content"))
            "get" -> readNode(query)
            "export" -> fail("api.unsupported", "Exporting a node as a share link is not supported by the Xray module")
            else -> fail("api.not_found", "Unsupported request")
        }
    }

    private suspend fun addNode(content: String): JsonElement {
        val text = content.trim()
        if (text.isEmpty()) fail("node.import", "Nothing to import")
        val result = RootShell.exec("sh ${shQuote(CLI)} config add ${shQuote(text)}")
        if (!result.ok) fail("node.import", result.message().ifEmpty { "Import failed" })
        return buildJsonObject { put("group_id", DEFAULT_GROUP) }
    }

    /** Accepts one link, one link per line, a WireGuard config, or an Xray `outbounds` JSON file. */
    private suspend fun importNodes(content: String): JsonElement {
        val text = content.trim()
        if (text.isEmpty()) fail("node.import", "Nothing to import")
        if (text.startsWith("{")) {
            val root = runCatching { json.parseToJsonElement(text) as? JsonObject }.getOrNull()
                ?: fail("node.import", "The file is not valid JSON")
            val document = when {
                root["outbounds"] is JsonArray -> root
                root["protocol"] != null -> buildJsonObject { put("outbounds", JsonArray(listOf(root))) }
                else -> fail("node.import", "JSON must contain an \"outbounds\" array")
            }
            val file = "$OUTBOUNDS_DIR/$DEFAULT_GROUP/import_${System.currentTimeMillis()}.json"
            val result = RootShell.exec("cat > ${shQuote(file)}", stdin = document.toString())
            if (!result.ok) fail("node.import", result.message().ifEmpty { "Could not save the node" })
            return buildJsonObject { put("group_id", DEFAULT_GROUP) }
        }
        if (text.contains("[Interface]", ignoreCase = true)) return addNode(text)

        val links = text.lines().map(String::trim).filter { it.contains("://") }
        if (links.isEmpty()) fail("node.import", "No supported node links were found")
        var imported = 0
        var lastError = ""
        for (link in links) {
            val result = RootShell.exec("sh ${shQuote(CLI)} config add ${shQuote(link)}")
            if (result.ok) imported++ else lastError = result.message()
        }
        if (imported == 0) fail("node.import", lastError.ifEmpty { "Import failed" })
        return buildJsonObject { put("group_id", DEFAULT_GROUP); put("imported", imported) }
    }

    private suspend fun editNode(body: JsonObject): JsonElement {
        val path = nodeFilePath(body.text("group_id"), body.text("node_tag"))
        val content = body.text("content")
        val parsed = runCatching { json.parseToJsonElement(content) as? JsonObject }.getOrNull()
            ?: fail("node.edit", "The node is not valid JSON")
        if (parsed["outbounds"] !is JsonArray) fail("node.edit", "The node must contain an \"outbounds\" array")
        val result = RootShell.exec("cat > ${shQuote(path)}", stdin = content)
        if (!result.ok) fail("node.edit", result.message().ifEmpty { "Could not save the node" })
        return JsonObject(emptyMap())
    }

    private suspend fun readNode(query: Map<String, String>): JsonElement {
        val path = nodeFilePath(query["group_id"].orEmpty(), query["node_tag"].orEmpty())
        val result = RootShell.exec("cat ${shQuote(path)}")
        if (!result.ok) fail("node.not_found", "Node not found")
        return runCatching { json.parseToJsonElement(result.out) }.getOrElse { fail("node.edit", "The node is not valid JSON") }
    }

    private suspend fun removeNode(query: Map<String, String>): JsonElement {
        val path = nodeFilePath(query["group_id"].orEmpty(), query["node_tag"].orEmpty())
        val current = parseConf(RootShell.exec("cat ${shQuote(MODULE_CONF)}").out)["CURRENT_CONFIG"].orEmpty()
        if (current == path) fail("node.remove", "This node is currently in use. Switch to another node first")
        val result = RootShell.exec("rm -f ${shQuote(path)}")
        if (!result.ok) fail("node.remove", result.message().ifEmpty { "Could not remove the node" })
        return JsonObject(emptyMap())
    }

    /** Detailed scan used for latency probing. */
    suspend fun scanWithContent(): List<GroupScan> = scan(true)
}
