package io.github.biulight.phone_identity

import java.math.BigInteger
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.PrivateKey
import java.security.Signature

internal data class WifiDiscoveryQuery(
    val purpose: PhoneStreamSession.Purpose,
    val nonce: ByteArray,
    val desktopId: ByteArray,
    val identityId: ByteArray,
) {
    fun clear() {
        nonce.fill(0)
        desktopId.fill(0)
        identityId.fill(0)
    }
}

/** Strict fixed-width discovery framing. Discovery selects a route but never authorizes pairing or unwrap. */
internal object WifiDiscoveryCodec {
    const val DISCOVERY_PORT = 47_141
    const val QUERY_BYTES = 72
    const val SIGNATURE_BYTES = 64
    const val SIGNED_RESPONSE_BYTES = QUERY_BYTES + SIGNATURE_BYTES
    private const val VERSION = 1
    private const val QUERY = 1
    private const val RESPONSE = 2
    private val MAGIC = byteArrayOf(0x41, 0x50, 0x57, 0x44)
    private val SIGNATURE_DOMAIN =
        "age-plugin-phone/wifi-discovery-response/v1".toByteArray(Charsets.US_ASCII)

    fun parseQuery(encoded: ByteArray, expectedPurpose: PhoneStreamSession.Purpose): WifiDiscoveryQuery {
        if (encoded.size != QUERY_BYTES || !encoded.copyOfRange(0, 4).contentEquals(MAGIC) ||
            unsignedShort(encoded, 4) != VERSION || unsigned(encoded[6]) != QUERY ||
            unsigned(encoded[7]) != expectedPurpose.code
        ) throw StreamTransportException()
        val query = WifiDiscoveryQuery(
            expectedPurpose,
            encoded.copyOfRange(8, 40),
            encoded.copyOfRange(40, 56),
            encoded.copyOfRange(56, 72),
        )
        if (expectedPurpose == PhoneStreamSession.Purpose.PAIRING && query.identityId.any { it != 0.toByte() }) {
            query.clear()
            throw StreamTransportException()
        }
        return query
    }

    fun responsePrefix(query: WifiDiscoveryQuery): ByteArray = ByteArray(QUERY_BYTES).also { response ->
        MAGIC.copyInto(response, 0)
        response[4] = 0
        response[5] = VERSION.toByte()
        response[6] = RESPONSE.toByte()
        response[7] = query.purpose.code.toByte()
        query.nonce.copyInto(response, 8)
        query.desktopId.copyInto(response, 40)
        query.identityId.copyInto(response, 56)
    }

    fun signedResponse(query: WifiDiscoveryQuery, key: PrivateKey): ByteArray {
        val response = responsePrefix(query)
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(key)
        signer.update(SIGNATURE_DOMAIN)
        signer.update(byteArrayOf(0))
        signer.update(response)
        return response + derToCompact(signer.sign(), P256_ORDER)
    }

    private fun derToCompact(der: ByteArray, order: BigInteger): ByteArray {
        if (der.size < 8 || der[0] != 0x30.toByte() || unsigned(der[1]) != der.size - 2) {
            throw StreamTransportException()
        }
        var offset = 2
        fun integer(): ByteArray {
            if (offset + 2 > der.size || der[offset++] != 0x02.toByte()) {
                throw StreamTransportException()
            }
            val size = unsigned(der[offset++])
            if (size !in 1..33 || offset + size > der.size) throw StreamTransportException()
            return der.copyOfRange(offset, offset + size).also { offset += size }
        }
        val r = BigInteger(1, integer())
        var s = BigInteger(1, integer())
        if (offset != der.size) throw StreamTransportException()
        if (s > order.shiftRight(1)) s = order.subtract(s)
        return fixed(r) + fixed(s)
    }

    private fun fixed(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        val unsigned = if (raw.size == 33 && raw[0] == 0.toByte()) raw.copyOfRange(1, 33) else raw
        if (unsigned.size > 32) throw StreamTransportException()
        return ByteArray(32).also { unsigned.copyInto(it, 32 - unsigned.size) }
    }

    private fun unsigned(value: Byte): Int = value.toInt() and 0xff
    private fun unsignedShort(value: ByteArray, offset: Int): Int =
        (unsigned(value[offset]) shl 8) or unsigned(value[offset + 1])

    private val P256_ORDER = BigInteger(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        16,
    )
}

/** Reuses one public signature for transport retransmits of the exact same strict query. */
internal class WifiDiscoveryResponseCache : AutoCloseable {
    private var query: ByteArray? = null
    private var response: ByteArray? = null

    @Synchronized
    fun responseFor(encodedQuery: ByteArray, create: () -> ByteArray?): ByteArray? {
        if (query?.contentEquals(encodedQuery) == true) return response?.copyOf()
        val created = create() ?: return null
        query?.fill(0)
        response?.fill(0)
        query = encodedQuery.copyOf()
        response = created.copyOf()
        return created
    }

    @Synchronized
    override fun close() {
        query?.fill(0)
        response?.fill(0)
        query = null
        response = null
    }
}

/** One responder owned by one foreground TCP listener. Closing it interrupts receive immediately. */
internal class WifiDiscoveryResponder private constructor(
    private val socket: DatagramSocket,
    private val purpose: PhoneStreamSession.Purpose,
    private val responseFor: (WifiDiscoveryQuery) -> ByteArray?,
) : AutoCloseable {
    private val responseCache = WifiDiscoveryResponseCache()
    @Volatile
    private var closed = false
    private val worker = Thread(::run, "phone-wifi-discovery").apply {
        isDaemon = true
        start()
    }

    private fun run() {
        val buffer = ByteArray(WifiDiscoveryCodec.QUERY_BYTES + 1)
        while (!closed) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(packet)
                if (packet.length != WifiDiscoveryCodec.QUERY_BYTES) continue
                val encoded = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                val query = try {
                    WifiDiscoveryCodec.parseQuery(encoded, purpose)
                } catch (_: Exception) {
                    encoded.fill(0)
                    continue
                }
                val response = try {
                    responseCache.responseFor(encoded) { responseFor(query) }
                } catch (_: Exception) {
                    null
                } finally {
                    query.clear()
                    encoded.fill(0)
                } ?: continue
                try {
                    val target = InetSocketAddress(packet.address, packet.port)
                    socket.send(DatagramPacket(response, response.size, target))
                } finally {
                    response.fill(0)
                }
            } catch (_: Exception) {
                if (!closed) continue
            }
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        socket.close()
        if (Thread.currentThread() !== worker) runCatching { worker.join(1_000) }
        responseCache.close()
    }

    companion object {
        fun start(
            purpose: PhoneStreamSession.Purpose,
            responseFor: (WifiDiscoveryQuery) -> ByteArray?,
        ): WifiDiscoveryResponder {
            val socket = DatagramSocket(null)
            try {
                socket.reuseAddress = false
                socket.broadcast = true
                socket.bind(InetSocketAddress(InetAddress.getByName("0.0.0.0"), WifiDiscoveryCodec.DISCOVERY_PORT))
                return WifiDiscoveryResponder(socket, purpose, responseFor)
            } catch (error: Exception) {
                socket.close()
                throw StreamTransportException(error)
            }
        }
    }
}
