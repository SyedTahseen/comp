package com.fanjv.netproxy.core.api

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

/** Install location of the Xray based NetProxy module. */
internal const val MODULE_DIR = "/data/adb/modules/netproxy"
internal const val OUTBOUNDS_DIR = "$MODULE_DIR/config/xray/outbounds"
internal const val MODULE_CONF = "$MODULE_DIR/config/module.conf"
internal const val TPROXY_CONF = "$MODULE_DIR/config/tproxy/tproxy.conf"
internal const val XRAY_BIN = "$MODULE_DIR/bin/xray"
internal const val CLI = "$MODULE_DIR/scripts/cli"
internal const val COMMON_SH = "$MODULE_DIR/scripts/utils/common.sh"

internal class ShellResult(val code: Int, val out: String, val err: String) {
    val ok: Boolean get() = code == 0

    /** Last meaningful line of output, without terminal colour codes. */
    fun message(): String =
        (err + "\n" + out).stripAnsi().lines().map(String::trim).lastOrNull(String::isNotEmpty).orEmpty()
}

private val ansiPattern = Regex("\u001B\\[[0-9;]*[A-Za-z]")
internal fun String.stripAnsi(): String = replace(ansiPattern, "")

/** Quotes a value for safe use as a single POSIX shell word. */
internal fun shQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

/** Parses `KEY=value` / `KEY="value"` lines of the module's shell style config files. */
internal fun parseConf(text: String): Map<String, String> =
    text.lineSequence()
        .map(String::trim)
        .filter { it.isNotEmpty() && !it.startsWith("#") && it.contains('=') }
        .associate { line ->
            line.substringBefore('=').trim() to line.substringAfter('=').trim().removeSurrounding("\"")
        }

/** Runs commands through `su`. All module access of the manager goes through here. */
internal object RootShell {
    private const val DEFAULT_TIMEOUT_MS = 120_000L

    private fun start(command: String): Process = try {
        ProcessBuilder("su", "-c", command).start()
    } catch (_: IOException) {
        throw ModuleApiException("api.root_unavailable", "Root access (su) is not available")
    }

    suspend fun exec(command: String, stdin: String? = null, timeoutMs: Long = DEFAULT_TIMEOUT_MS): ShellResult =
        withContext(Dispatchers.IO) {
            val process = start(command)
            try {
                coroutineScope {
                    val watchdog = launch { delay(timeoutMs); process.destroyForcibly() }
                    val err = async { process.errorStream.bufferedReader().readText() }
                    val out = async { process.inputStream.bufferedReader().readText() }
                    if (stdin != null) process.outputStream.use { it.write(stdin.toByteArray(Charsets.UTF_8)) }
                    else process.outputStream.close()
                    val result = ShellResult(process.waitFor(), out.await(), err.await())
                    watchdog.cancel()
                    result
                }
            } finally {
                process.destroy()
            }
        }

    /** Streams the command's stdout (binary safe) into [destination]. */
    suspend fun execToFile(command: String, destination: File, timeoutMs: Long = DEFAULT_TIMEOUT_MS) {
        withContext(Dispatchers.IO) {
            val process = start(command)
            try {
                coroutineScope {
                    val watchdog = launch { delay(timeoutMs); process.destroyForcibly() }
                    val err = async { process.errorStream.bufferedReader().readText() }
                    process.outputStream.close()
                    destination.outputStream().use { sink -> process.inputStream.copyTo(sink) }
                    val code = process.waitFor()
                    watchdog.cancel()
                    if (code != 0) {
                        throw ModuleApiException("api.download_failed", err.await().stripAnsi().trim().ifEmpty { "Export failed" })
                    }
                }
            } finally {
                process.destroy()
            }
        }
    }
}
