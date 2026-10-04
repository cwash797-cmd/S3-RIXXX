package io.nekohasekai.sagernet.fmt

import android.app.Application
import io.nekohasekai.sagernet.fmt.trusttunnel.TrustTunnelTest
import io.nekohasekai.sagernet.fmt.xhttp.*
import io.nekohasekai.sagernet.group.RawUpdater
import kotlinx.coroutines.runBlocking
import okio.ByteString.Companion.encodeUtf8
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.URLEncoder

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class, shadows = [TrustTunnelTest.NativeLogShadow::class, TrustTunnelTest.AndroidSocketReflectionShadow::class])
class S3RegressionTest {
    private val encryption = "mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    private fun storage() = JSONObject().put("version", 1).put("endpoint", "https://hb.ru-msk.vkcloud-storage.ru")
        .put("region", "ru-msk").put("bucket", "test-bucket").put("prefix", "probe-tests/data/android1")
        .put("accessKey", "CLIENT-FIXTURE").put("secretKey", "SECRET-FIXTURE")
    private fun link(data: JSONObject = storage()) = "vless://00000000-0000-4000-8000-000000000001@hb.ru-msk.vkcloud-storage.ru:443?type=xdrive&service=s3&encryption=$encryption&s3=" +
        URLEncoder.encode(data.toString().encodeUtf8().base64Url(), "UTF-8") + "#VK%20S3"

    @Test fun roundtripAndPersistence() {
        val bean = parseS3(link())
        val clone = bean.clone()
        assertTrue(clone.isS3)
        assertEquals("VK S3", clone.name)
        assertEquals(bean.s3Json, clone.s3Json)
        val restored = parseS3(clone.toUri())
        assertEquals(encryption, restored.vlessEncryption)
        assertEquals("CLIENT-FIXTURE", JSONObject(restored.s3Json).getString("accessKey"))
    }
    @Test fun transportUsesOnlyProtectedMapping() {
        val bean = parseS3(link()).apply { finalAddress = "127.0.0.1"; finalPort = 29001 }
        val result = JSONObject(bean.buildXrayConfig(29000, 1))
        assertEquals("warning", result.getJSONObject("log").getString("loglevel"))
        assertEquals(1, result.getJSONArray("outbounds").length())
        val outbound = result.getJSONArray("outbounds").getJSONObject(0)
        val stream = outbound.getJSONObject("streamSettings")
        assertEquals("xdrive", stream.getString("network"))
        assertEquals("127.0.0.1", stream.getString("address"))
        assertEquals(29001, stream.getInt("port"))
        val cfg = stream.getJSONObject("xdriveSettings")
        assertEquals("S3", cfg.getString("service"))
        val creds = JSONObject(cfg.getJSONArray("secrets").getString(0))
        assertEquals("https://hb.ru-msk.vkcloud-storage.ru", creds.getString("endpoint"))
        val users = outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users")
        assertEquals(encryption, users.getJSONObject(0).getString("encryption"))
    }
    @Test fun unmappedTransportCannotDialDirectly() {
        val bean = parseS3(link()).apply { finalAddress = serverAddress; finalPort = serverPort }
        assertThrows(IllegalArgumentException::class.java) { bean.buildXrayConfig(29000, 0) }
    }
    @Test fun rejectInsecureAndAmbiguousLinks() {
        for (bad in listOf(link().replace(encryption, "none"), link().replace(".1rtt.", ".0rtt."),
            link().replace("#VK%20S3", "&type=tcp"), link(storage().put("endpoint", "http://hb.ru-msk.vkcloud-storage.ru")),
            link(storage().put("prefix", "../other")), link(storage().put("endpoint", "https://evil.invalid")))) {
            assertThrows(IllegalArgumentException::class.java) { parseS3(bad) }
        }
    }
    @Test fun plainAndBase64Subscriptions() = runBlocking {
        for (text in listOf(link(), link().encodeUtf8().base64())) {
            val beans = RawUpdater.parseRaw(text)!!
            assertEquals(1, beans.size)
            assertTrue((beans.single() as XhttpBean).isS3)
        }
    }
    @Test fun accountsAtSameEndpointAreNotDeduplicated() {
        val one = parseS3(link())
        val two = parseS3(link(storage().put("prefix", "probe-tests/data/android2")))
        assertNotEquals(moe.matsuri.nb4a.Protocols.Deduplication(one, "VLESS-S3"),
            moe.matsuri.nb4a.Protocols.Deduplication(two, "VLESS-S3"))
    }
}
