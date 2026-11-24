package com.fanjv.netproxy.core.api

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayOutputStream

/**
 * Lists installed apps for the per-app proxy page. The Xray module has no helper for this, and the manager
 * runs on the same device, so the Android package manager is used directly (needs QUERY_ALL_PACKAGES).
 */
internal class XrayAndroidApps(private val context: Context) {
    private val iconSize = 128

    @Suppress("DEPRECATION")
    suspend fun snapshot(): JsonObject = withContext(Dispatchers.Default) {
        val manager = context.packageManager
        val entries = manager.getInstalledApplications(0).map { info ->
            val pkg = runCatching { manager.getPackageInfo(info.packageName, 0) }.getOrNull()
            val version = when {
                pkg == null -> 0L
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> pkg.longVersionCode
                else -> pkg.versionCode.toLong()
            }
            val updated = pkg?.lastUpdateTime ?: 0L
            val label = runCatching { manager.getApplicationLabel(info).toString() }.getOrDefault(info.packageName)
            val system = info.flags and ApplicationInfo.FLAG_SYSTEM != 0 &&
                info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0
            Triple(label, info, buildJsonObject {
                put("package_name", info.packageName)
                put("label", label)
                put("uid", info.uid)
                put("system", system)
                put("version_code", version)
                put("last_update_time", updated)
                put("icon_key", "${info.packageName}~$version~$updated")
            })
        }.sortedBy { it.first.lowercase() }

        val apps = JsonArray(entries.map { it.third })
        buildJsonObject {
            put("users", JsonArray(listOf(buildJsonObject {
                put("id", 0)
                put("name", "User 0")
                put("revision", Integer.toHexString(entries.joinToString("|") { it.second.packageName }.hashCode()))
                put("apps", apps)
            })))
        }
    }

    suspend fun icon(key: String): ByteArray = withContext(Dispatchers.Default) {
        val packageName = key.substringBefore('~')
        try {
            val drawable = context.packageManager.getApplicationIcon(packageName)
            val bitmap = Bitmap.createBitmap(iconSize, iconSize, Bitmap.Config.ARGB_8888)
            drawable.setBounds(0, 0, iconSize, iconSize)
            drawable.draw(Canvas(bitmap))
            ByteArrayOutputStream().use { output ->
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)
                output.toByteArray()
            }
        } catch (_: PackageManager.NameNotFoundException) {
            throw ModuleApiException("api.image_failed", "Icon not found: $packageName")
        }
    }
}
