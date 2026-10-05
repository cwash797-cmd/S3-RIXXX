// SPDX-License-Identifier: GPL-3.0-or-later
package io.nekohasekai.sagernet.fmt.xhttp

import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.linkBuilder
import io.nekohasekai.sagernet.ktx.toLink
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.encodeUtf8
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

val XhttpBean.isS3: Boolean get() = !s3Json.isNullOrBlank()

fun isS3Link(link: String): Boolean = runCatching {
    ("https://" + link.substringAfter("://")).toHttpUrlOrNull()?.queryParameter("type") == "xdrive"
}.getOrDefault(false)

private fun validatedStorage(raw: String): JSONObject {
    require(raw.length <= 8192) { "S3 profile too large" }
    val data = JSONObject(raw)
    val allowed = setOf("version", "endpoint", "region", "bucket", "prefix", "accessKey", "secretKey")
    require(data.keys().asSequence().all { it in allowed }) { "Unknown S3 profile fields" }
    require(data.optInt("version") == 1) { "Unsupported S3 profile version" }
    val endpoint = data.getString("endpoint").toHttpUrlOrNull()
        ?: throw IllegalArgumentException("Invalid S3 endpoint")
    require(endpoint.scheme == "https" && endpoint.port == 443 && endpoint.username.isEmpty() &&
        endpoint.password.isEmpty() && endpoint.encodedPath == "/" && endpoint.query == null && endpoint.fragment == null) {
        "S3 requires an HTTPS origin on port 443"
    }
    require(endpoint.host in setOf("hb.ru-msk.vkcloud-storage.ru", "hb.vkcloud-storage.ru")) {
        "This S3 profile must use a supported VK endpoint"
    }
    require(data.getString("bucket").matches(Regex("[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"))) { "Invalid S3 bucket" }
    require(data.getString("prefix").matches(Regex("[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*/?"))) { "Isolated S3 prefix required" }
    for (key in listOf("accessKey", "secretKey", "region")) {
        val value = data.getString(key)
        require(value.isNotBlank() && value.length <= 1024 && value.none { it == '\r' || it == '\n' }) { "Invalid S3 credentials" }
    }
    return data
}

fun parseS3(link: String): XhttpBean {
    require(link.length <= 16384) { "S3 link too large" }
    val url = ("https://" + link.substringAfter("://")).toHttpUrlOrNull()
        ?: throw IllegalArgumentException("Invalid S3 link")
    require(url.queryParameterNames.all { url.queryParameterValues(it).size == 1 }) { "Duplicate S3 parameters" }
    require(url.queryParameter("type") == "xdrive" && url.queryParameter("service") == "s3") { "Unsupported XDRIVE service" }
    val payload = url.queryParameter("s3")?.decodeBase64()?.utf8()
        ?: throw IllegalArgumentException("Missing S3 profile")
    val storage = validatedStorage(payload)
    val endpoint = storage.getString("endpoint").toHttpUrlOrNull()!!
    require(url.host == endpoint.host && url.port == endpoint.port) { "S3 authority must match endpoint" }
    require(url.queryParameter("security").isNullOrBlank() || url.queryParameter("security") == "none") { "Unexpected outer security" }
    require(url.queryParameter("flow").isNullOrBlank()) { "VLESS flow is not supported over S3" }
    val encryption = url.queryParameter("encryption") ?: ""
    require(encryption.startsWith("mlkem768x25519plus.") && ".1rtt." in encryption && encryption.length <= 4096) {
        "S3 requires VLESS Encryption with 1rtt server authentication"
    }
    val id = UUID.fromString(url.username).toString()
    return XhttpBean().apply {
        initializeDefaultValues()
        serverAddress = endpoint.host
        serverPort = endpoint.port
        uuid = id
        s3Json = storage.toString()
        vlessEncryption = encryption
        name = url.fragment ?: "VK S3"
        security = "none"
    }
}

fun XhttpBean.toS3Uri(): String {
    validatedStorage(s3Json)
    return linkBuilder().host(serverAddress).port(serverPort).username(uuid)
        .addQueryParameter("type", "xdrive").addQueryParameter("service", "s3")
        .addQueryParameter("encryption", vlessEncryption)
        .addQueryParameter("s3", s3Json.encodeUtf8().base64Url())
        .fragment(name).toLink("vless")
}

fun XhttpBean.buildS3Config(port: Int): String {
    val data = validatedStorage(s3Json)
    val endpoint = data.getString("endpoint").toHttpUrlOrNull()!!
    require(serverAddress == endpoint.host && serverPort == 443) { "S3 endpoint mismatch" }
    require(finalAddress == LOCALHOST && finalPort in 1..65535 && finalPort != port) { "S3 requires the protected upstream mapping" }
    // Revalidate imported/serialized credentials and the encryption field at runtime.
    parseS3(toS3Uri())
    val secret = JSONObject(data.toString()).apply { remove("version"); remove("prefix") }
    val stream = JSONObject().apply {
        put("network", "xdrive")
        // XDRIVE's HTTP service dialer reads StreamConfig.Destination, NOT vnext.
        // Explicitly bind it to sing-box's protected mapping; do not dial VK here.
        put("address", finalAddress)
        put("port", finalPort)
        put("security", "none") // HTTPS to S3 is verified inside the backend.
        put("xdriveSettings", JSONObject().apply {
            put("service", "S3")
            put("remoteFolder", data.getString("prefix"))
            put("secrets", JSONArray().put(secret.toString()))
            put("segmentBytes", 262144)
            put("flushIntervalMs", 30)
            put("pollIntervalMs", 150)
            put("maxPollIntervalMs", 1200)
            put("concurrency", 4)
            put("sessionTtlSeconds", 300)
        })
    }
    val user = JSONObject().put("id", uuid).put("encryption", vlessEncryption)
    val target = JSONObject().put("address", finalAddress).put("port", finalPort)
        .put("users", JSONArray().put(user))
    val outbound = JSONObject().put("tag", "proxy").put("protocol", "vless")
        .put("settings", JSONObject().put("vnext", JSONArray().put(target)))
        .put("streamSettings", stream)
        .put("mux", JSONObject().put("enabled", true).put("concurrency", 8))
    val inbound = JSONObject().put("listen", LOCALHOST).put("port", port).put("protocol", "socks")
        .put("settings", JSONObject().put("auth", "noauth").put("udp", true))
    return JSONObject().put("log", JSONObject().put("loglevel", "warning"))
        .put("inbounds", JSONArray().put(inbound)).put("outbounds", JSONArray().put(outbound)).toString()
}
