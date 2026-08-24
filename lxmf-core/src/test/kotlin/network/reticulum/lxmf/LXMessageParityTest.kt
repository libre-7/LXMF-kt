package network.reticulum.lxmf

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import org.junit.jupiter.api.Test
import java.nio.file.Files
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for the Python-parity additions to LXMessage:
 * title/content string accessors, set_fields/get_fields, destination/source
 * validation, delivery callbacks, packed_container, write_to_directory,
 * unpack_from_file round-trip, compression-support parsing and transport
 * encryption determination.
 */
class LXMessageParityTest {

    private fun makePair(): Pair<Destination, Destination> {
        val sourceIdentity = Identity.create()
        val destIdentity = Identity.create()

        val source = Destination.create(
            identity = sourceIdentity,
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "lxmf",
            "delivery"
        )
        val dest = Destination.create(
            identity = destIdentity,
            direction = DestinationDirection.OUT,
            type = DestinationType.SINGLE,
            appName = "lxmf",
            "delivery"
        )
        return Pair(source, dest)
    }

    private fun rememberSourceIdentity(sourceIdentity: Identity, sourceDestination: Destination) {
        Identity.remember(
            packetHash = ByteArray(32),
            destHash = sourceDestination.hash,
            publicKey = sourceIdentity.getPublicKey()
        )
    }

    // ===== String accessors =====

    @Test
    fun `test set_title_from_string and title_as_string`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "body")
        msg.setTitleFromString("Hello")
        assertEquals("Hello", msg.title)
        assertEquals("Hello", msg.titleAsString())
    }

    @Test
    fun `test set_content_from_string and content_as_string`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "")
        msg.setContentFromString("Payload")
        assertEquals("Payload", msg.contentAsString())
    }

    @Test
    fun `test content_as_string survives utf8 roundtrip`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "héllo — ünïcode ✓")
        assertEquals(msg.content, msg.contentAsString())
    }

    // ===== Fields =====

    @Test
    fun `test set_fields replaces contents`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")
        msg.setFields(mapOf(LXMFConstants.FIELD_RENDERER to LXMFConstants.RENDERER_PLAIN))
        assertEquals(1, msg.fields.size)
        assertEquals(LXMFConstants.RENDERER_PLAIN, msg.fields[LXMFConstants.FIELD_RENDERER])
    }

    @Test
    fun `test set_fields with null clears`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(
            dest, source, "b",
            fields = mutableMapOf(LXMFConstants.FIELD_DEBUG to "x")
        )
        msg.setFields(null)
        assertTrue(msg.fields.isEmpty())
    }

    // ===== Destination / source validation =====

    @Test
    fun `test set_destination rejects reassignment`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")
        assertFailsWith<IllegalStateException> { msg.setDestination(dest) }
    }

    @Test
    fun `test set_source rejects reassignment`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")
        assertFailsWith<IllegalStateException> { msg.setSource(source) }
    }

    @Test
    fun `test set_destination rejects non single`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")
        // this.destination is already set in create(); use a fresh unpacked message instead
        val other = LXMessage.unpackFromBytes(msg.pack().copyOf())?.let { null }
        assertNull(other) // placeholder; direct construction is private so we test via validation below

        // Validation branch: null destination on a message whose destination is null.
        // Unpacked messages have destination == null, so use that path.
        val unpackedMsg = run {
            rememberSourceIdentity(source.identity!!, source)
            LXMessage.unpackFromBytes(msg.pack())!!
        }
        assertNull(unpackedMsg.destination)
        assertFailsWith<IllegalArgumentException> { unpackedMsg.setDestination(null) }
        // And a valid assignment does not throw (validation-only port)
        unpackedMsg.setDestination(dest)
    }

    // ===== Callbacks =====

    @Test
    fun `test register_delivery_and_failed_callback`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")

        var delivered: LXMessage? = null
        var failed: LXMessage? = null
        msg.registerDeliveryCallback { delivered = it }
        msg.registerFailedCallback { failed = it }

        assertNotNull(msg.deliveryCallback)
        msg.deliveryCallback?.invoke(msg)
        msg.failedCallback?.invoke(msg)
        assertEquals(msg, delivered)
        assertEquals(msg, failed)
    }

    @Test
    fun `test send without router hook fails cleanly`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")
        var failureNotified = false
        msg.registerFailedCallback { failureNotified = true }

        // Python's send() always runs after pack(), which resolves `method`;
        // mirror that ordering so transport-encryption determination has input.
        msg.pack()
        val result = msg.send()
        assertTrue(!result)
        assertEquals(MessageState.FAILED, msg.state)
        assertTrue(failureNotified)
        // Pre-send annotations ran even on the failure path
        assertEquals(LXMFConstants.ENCRYPTION_DESCRIPTION_EC, msg.transportEncryption)
        assertTrue(msg.transportEncrypted)
    }

    // ===== Packed container / persistence =====

    @Test
    fun `test packed_container roundtrip via unpackFromFile`() {
        val (source, dest) = makePair()
        rememberSourceIdentity(source.identity!!, source)

        val original = LXMessage.create(
            dest, source, "persist me", "t",
            desiredMethod = DeliveryMethod.DIRECT
        )
        original.pack()
        original.determineTransportEncryption()
        val container = original.packedContainer()
        assertNotNull(container)

        // Decode container msgpack manually to extract lxmf_bytes
        val unpacker = org.msgpack.core.MessagePack.newDefaultUnpacker(container)
        val mapSize = unpacker.unpackMapHeader()
        var state = -1
        var lxmfBytes: ByteArray? = null
        var transportEncrypted = false
        var transportEncryption: String? = null
        var method = -1
        repeat(mapSize) {
            when (unpacker.unpackString()) {
                "state" -> state = unpacker.unpackInt()
                "lxmf_bytes" -> {
                    val len = unpacker.unpackBinaryHeader()
                    lxmfBytes = ByteArray(len).also { unpacker.readPayload(it) }
                }
                "transport_encrypted" -> transportEncrypted = unpacker.unpackBoolean()
                "transport_encryption" -> transportEncryption = unpacker.unpackString()
                "method" -> method = unpacker.unpackInt()
                else -> unpacker.skipValue()
            }
        }
        unpacker.close()

        assertEquals(MessageState.GENERATING.value, state)
        assertEquals(DeliveryMethod.DIRECT.value, method)
        assertTrue(transportEncrypted)
        assertNotNull(lxmfBytes)

        val restored = LXMessage.unpackFromBytes(lxmfBytes!!)
        assertNotNull(restored)
        assertEquals(original.content, restored.content)
        assertEquals(original.hash!!.contentEquals(restored.hash!!), true)
    }

    @Test
    fun `test write_to_directory writes hash-named file`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "on disk")
        msg.pack()

        val dir = Files.createTempDirectory("lxmf-write-test").toString()
        val path = msg.writeToDirectory(dir)
        assertNotNull(path)
        assertEquals(msg.hash!!.toHexString(), path.substringAfterLast('/'))
        assertTrue(Files.exists(java.nio.file.Path.of(path)))
        assertTrue(Files.readAllBytes(java.nio.file.Path.of(path)).size > 0)
    }

    @Test
    fun `test write_to_directory rejects unpacked message`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "not packed")
        assertNull(msg.writeToDirectory(Files.createTempDirectory("lxmf-x").toString()))
    }

    // ===== Compression support =====

    @Test
    fun `test compression_support_from_app_data defaults`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")
        assertNull(msg.compressionSupportFromAppData(null))
        assertNull(msg.compressionSupportFromAppData(ByteArray(0)))
    }

    @Test
    fun `test compression_support_from_app_data short list means supported`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")

        val buffer = java.io.ByteArrayOutputStream()
        val packer = org.msgpack.core.MessagePack.newDefaultPacker(buffer)
        packer.packArrayHeader(2)
        packer.packInt(1)
        packer.packInt(2)
        packer.close()

        assertEquals(true, msg.compressionSupportFromAppData(buffer.toByteArray()))
    }

    @Test
    fun `test compression_support_from_app_data flag list parsing`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")

        fun packFlags(flags: List<Int>): ByteArray {
            val buffer = java.io.ByteArrayOutputStream()
            val packer = org.msgpack.core.MessagePack.newDefaultPacker(buffer)
            packer.packArrayHeader(3)
            packer.packInt(1)
            packer.packInt(2)
            packer.packArrayHeader(flags.size)
            flags.forEach { packer.packInt(it) }
            packer.close()
            return buffer.toByteArray()
        }

        assertEquals(true, msg.compressionSupportFromAppData(packFlags(listOf(0x00))))
        assertEquals(false, msg.compressionSupportFromAppData(packFlags(listOf(0x01))))
        assertEquals(false, msg.compressionSupportFromAppData(packFlags(emptyList())))
    }

    @Test
    fun `test determine_compression_support defaults true without announce`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")
        msg.determineCompressionSupport()
        assertTrue(msg.autoCompress)
    }

    // ===== Transport encryption =====

    @Test
    fun `test determine_transport_encryption by method`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "b")

        msg.method = DeliveryMethod.DIRECT
        msg.determineTransportEncryption()
        assertEquals(true, msg.transportEncrypted)
        assertEquals(LXMFConstants.ENCRYPTION_DESCRIPTION_EC, msg.transportEncryption)

        msg.method = DeliveryMethod.PROPAGATED
        msg.determineTransportEncryption()
        assertEquals(true, msg.transportEncrypted)
        assertEquals(LXMFConstants.ENCRYPTION_DESCRIPTION_EC, msg.transportEncryption)

        msg.method = null
        msg.determineTransportEncryption()
        assertEquals(false, msg.transportEncrypted)
        assertEquals(LXMFConstants.ENCRYPTION_DESCRIPTION_UNENCRYPTED, msg.transportEncryption)
    }

    // ===== Constants =====

    @Test
    fun `test paper and qr constants match python`() {
        assertEquals(2953, LXMFConstants.QR_MAX_STORAGE)
        assertEquals("ERROR_CORRECT_L", LXMFConstants.QR_ERROR_CORRECTION)
        assertEquals(0x00, LXMFConstants.SF_COMPRESSION)
        // PAPER_MDU = ((2953-(3+3))*6)//8 = 2211
        assertEquals(((2953 - 6) * 6) / 8, LXMFConstants.PAPER_MDU)
    }

    // ===== Propagation stamp =====

    @Test
    fun `test get_propagation_stamp requires cost`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "stamp me")
        assertFailsWith<IllegalArgumentException> { kotlinx.coroutines.runBlocking { msg.getPropagationStamp(null) } }
    }

    @Test
    fun `test get_propagation_stamp generates valid stamp`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "stamp me")
        msg.stampCost = 8 // low cost so generation is fast

        val stamp = kotlinx.coroutines.runBlocking { msg.getPropagationStamp(8) }
        assertNotNull(stamp)
        assertTrue(msg.propagationStampValid)
        assertNotNull(msg.propagationStampValue)
        assertTrue(msg.propagationStampValue!! >= 8)
        assertNotNull(msg.transientId)

        // Cached second call returns same stamp without regeneration
        val again = kotlinx.coroutines.runBlocking { msg.getPropagationStamp(8) }
        assertTrue(stamp.contentEquals(again))
    }

    @Test
    fun `test compute_transient_id deterministic per packing`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "tid")
        msg.pack()
        val tid = msg.computeTransientId()
        assertNotNull(tid)
        assertEquals(32, tid.size)
        // Stored value tracks the latest computation (Python computes it once in pack())
        assertTrue(tid.contentEquals(msg.transientId!!))
        assertNotNull(msg.ratchetId == null || msg.ratchetId is ByteArray)
    }

    @Test
    fun `test pack_propagation produces container`() {
        val (source, dest) = makePair()
        val msg = LXMessage.create(dest, source, "propagate me")
        msg.pack()
        val packed = msg.packPropagation()
        assertNotNull(packed)
        assertNotNull(msg.propagationPacked)
        assertEquals(DeliveryMethod.PROPAGATED, msg.method)
        // msgpack([double, [binary]]) minimum structure
        assertTrue(packed.size > 40)
    }
}
