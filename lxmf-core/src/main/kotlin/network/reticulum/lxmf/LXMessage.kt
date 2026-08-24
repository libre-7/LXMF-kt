package network.reticulum.lxmf

import network.reticulum.common.toHexString
import network.reticulum.crypto.Hashes
import network.reticulum.common.DestinationType
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import org.msgpack.core.MessagePack
import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * LXMF Message class.
 *
 * Represents a message in the LXMF format with support for packing/unpacking
 * that is byte-perfect compatible with Python LXMF.
 *
 * Wire format:
 * ```
 * [0:16]   Destination hash (16 bytes)
 * [16:32]  Source hash (16 bytes)
 * [32:96]  Ed25519 signature (64 bytes)
 * [96:]    Msgpack payload
 * ```
 *
 * Payload structure (msgpack list):
 * ```
 * [0] timestamp  - float64 (UNIX epoch seconds)
 * [1] title      - bytes (UTF-8)
 * [2] content    - bytes (UTF-8)
 * [3] fields     - dict (extensible)
 * [4] stamp      - bytes (optional, 32 bytes proof-of-work)
 * ```
 */
class LXMessage private constructor(
    /** Destination for this message */
    val destination: Destination?,
    /** Source destination (sender) */
    val source: Destination?,
    /** Destination hash (always available even if destination is null) */
    val destinationHash: ByteArray,
    /** Source hash (always available even if source is null) */
    val sourceHash: ByteArray,
    /** Message title */
    var title: String,
    /** Message content */
    var content: String,
    /** Extended fields dictionary */
    val fields: MutableMap<Int, Any> = mutableMapOf(),
    /** Desired delivery method */
    var desiredMethod: DeliveryMethod? = null,
) {
    // ===== Message Identification =====

    /** Full message hash (32 bytes SHA-256) */
    var hash: ByteArray? = null
        private set

    /** Message ID (same as hash) */
    val messageId: ByteArray?
        get() = hash

    /** Transient ID for propagation (hash of encrypted data) */
    var transientId: ByteArray? = null
        private set

    // ===== State and Flags =====

    /** Current message state */
    var state: MessageState = MessageState.GENERATING

    /** Message representation (PACKET or RESOURCE) */
    var representation: MessageRepresentation = MessageRepresentation.UNKNOWN

    /** Actual delivery method used */
    var method: DeliveryMethod? = null

    /** Whether this is an incoming message */
    var incoming: Boolean = false

    /** Whether the signature has been validated */
    var signatureValidated: Boolean = false

    /** Reason why signature validation failed */
    var unverifiedReason: UnverifiedReason? = null

    // ===== Timestamps =====

    /** Message timestamp (UNIX epoch seconds as Double) */
    var timestamp: Double? = null

    // ===== Packed Data =====

    /** Packed message bytes (wire format) */
    var packed: ByteArray? = null
        private set

    /** Size of packed message */
    val packedSize: Int
        get() = packed?.size ?: 0

    /** Ed25519 signature (64 bytes) */
    var signature: ByteArray? = null
        private set

    /** Proof-of-work stamp (32 bytes, optional) */
    var stamp: ByteArray? = null

    /** Whether the stamp has been validated */
    var stampValid: Boolean = false

    /** Whether the stamp has been checked */
    var stampChecked: Boolean = false

    /** Validated stamp value (leading zero bits), or null if not checked */
    var stampValue: Int? = null

    /** Required stamp cost for this message */
    var stampCost: Int? = null

    /** Outbound ticket for stamp bypass */
    var outboundTicket: ByteArray? = null

    /** Whether to include a ticket in this message */
    var includeTicket: Boolean = false

    /** Whether to defer stamp generation (compute later in background) */
    var deferStamp: Boolean = false

    /** Packed bytes for PAPER delivery (destHash + encrypted rest) */
    var paperPacked: ByteArray? = null
        private set

    // ===== Encryption State =====

    /** Whether message was transport-encrypted */
    var transportEncrypted: Boolean = false

    /** Description of transport encryption used */
    var transportEncryption: String? = null

    /**
     * Progress of message delivery (0.0 to 1.0).
     *
     * `@Volatile` because writers and readers run on different threads.
     * Writers: `LXMRouter.processOpportunisticDelivery` (LXMRouter.kt:739,
     * 755), `LXMRouter.sendViaPropagation`'s Resource progressCallback
     * (LXMRouter.kt:1258), and `LXMRouter.sendViaLink`'s Resource
     * progressCallback + completion callback (LXMRouter.kt:1335, 1340) —
     * all dispatched from `processingScope` coroutines or RNS Resource
     * background threads. Readers: any caller polling progress for UI
     * display, plus the conformance bridge's `cmdLxmfGetMessageProgress`
     * (Main.kt:740) reading from the bridge's JSON-RPC dispatch thread.
     *
     * Without `@Volatile`, the JLS allows non-volatile `double` reads to
     * tear (§17.7) and offers no happens-before edge between the write
     * and a cross-thread read — visibility of the latest value is
     * implementation-defined. Python's GIL gives this for free; on JVM
     * `@Volatile` is the direct equivalent.
     */
    @Volatile var progress: Double = 0.0

    // ===== Callbacks =====

    /** Callback when message is delivered */
    var deliveryCallback: ((LXMessage) -> Unit)? = null

    /** Callback when message delivery fails */
    var failedCallback: ((LXMessage) -> Unit)? = null

    // ===== Delivery Tracking =====

    /** Number of delivery attempts made */
    var deliveryAttempts: Int = 0

    /** Next delivery attempt timestamp (milliseconds) */
    var nextDeliveryAttempt: Long? = null

    /**
     * Whether a path re-request has already been issued for a CLOSED delivery
     * link that never activated. Transient delivery-state — NOT part of the
     * packed wire format. Mirrors Python LXMF's dynamic `path_request_retried`
     * attribute (LXMRouter.py:2615-2618), which gates the never-activated retry
     * to exactly once.
     */
    var pathRequestRetried: Boolean = false

    // ===== Receive-time Packet Metadata =====
    //
    // The following fields are populated from the delivering Reticulum packet
    // when this LXMessage is constructed on the receive side. They are only
    // meaningful for live, in-path delivery (OPPORTUNISTIC and DIRECT);
    // outgoing messages do not carry them, and messages pulled from a
    // propagation node are intentionally left null because the original
    // in-path packet context is lost (the values would reflect the
    // propagation-node sync link, not the originating sender — which would
    // be misleading).

    /**
     * RSSI of the delivering packet (signed integer, typically dBm).
     *
     * Null for outgoing messages and for messages fetched from a propagation
     * node. For Resource-delivered (multi-packet) messages, this reflects the
     * phy stats of the link at the moment the Resource assembly concluded
     * (i.e. the final constituent packet). Requires the underlying Link to
     * have `trackPhyStats(true)` enabled for Resource-delivered messages; for
     * single-packet paths the value is copied from the delivering `Packet`
     * directly and is available unconditionally.
     */
    var receivedRssi: Int? = null

    /**
     * SNR of the delivering packet.
     *
     * Null for outgoing messages and for messages fetched from a propagation
     * node. See [receivedRssi] for semantics on Resource-delivered messages.
     */
    var receivedSnr: Float? = null

    /**
     * Hash of the interface the delivering packet arrived on.
     *
     * Null for outgoing messages and for messages fetched from a propagation
     * node. For Resource-delivered messages, reflects the interface the link
     * was attached to.
     */
    var receivingInterfaceHash: ByteArray? = null

    /**
     * Number of hops the delivering packet traveled to reach us.
     *
     * Null for outgoing messages and for messages fetched from a propagation
     * node. For Resource-delivered messages, reflects the link's expected
     * hop count (established at link-setup time), which is the correct hop
     * count for the Resource because every Resource constituent packet
     * travels the same hop path as the link itself.
     */
    var receivedHopCount: Int? = null

    /**
     * Pack the message into wire format.
     *
     * This creates the packed byte array that can be sent over the network.
     * The packing process:
     * 1. Create payload list: [timestamp, title, content, fields]
     * 2. Compute hash: SHA256(destHash + sourceHash + msgpack(payload))
     * 3. Sign: Ed25519(hashedPart + hash)
     * 4. Pack: destHash + sourceHash + signature + msgpack(payload)
     *
     * @return The packed message bytes
     * @throws IllegalStateException if source has no private key for signing
     */
    fun pack(): ByteArray {
        if (packed != null) {
            return packed!!
        }

        // Set timestamp if not set
        if (timestamp == null) {
            timestamp = System.currentTimeMillis() / 1000.0
        }

        // Get source identity for signing
        val sourceIdentity =
            source?.identity
                ?: throw IllegalStateException("Cannot pack message without source identity")
        require(sourceIdentity.hasPrivateKey) { "Cannot pack message: source has no private key" }

        // Build payload: [timestamp, title, content, fields]
        val payloadBytes = packPayload(timestamp!!, title, content, fields, stamp)

        // Build hashed part: destHash + sourceHash + msgpack(payload without stamp)
        val payloadWithoutStamp = packPayload(timestamp!!, title, content, fields, null)
        val hashedPart = destinationHash + sourceHash + payloadWithoutStamp

        // Compute message hash
        hash = Hashes.fullHash(hashedPart)

        // Build signed part: hashedPart + hash
        val signedPart = hashedPart + hash!!

        // Sign the message
        signature = sourceIdentity.sign(signedPart)
        signatureValidated = true

        // Build packed message: destHash + sourceHash + signature + payload
        packed = destinationHash + sourceHash + signature!! + payloadBytes

        // Determine delivery method and representation
        determineDeliveryMethod()

        return packed!!
    }

    /**
     * Re-pack the message with an updated stamp.
     *
     * Called after deferred stamp generation to update the packed bytes
     * with the newly generated stamp. The hash and signature don't change
     * because stamp is not included in the hashed/signed portion.
     */
    fun repackWithStamp() {
        if (stamp == null || hash == null || signature == null) return

        val payloadBytes = packPayload(timestamp!!, title, content, fields, stamp)
        packed = destinationHash + sourceHash + signature!! + payloadBytes

        determineDeliveryMethod()
    }

    /**
     * Determine the delivery method and representation based on message size.
     */
    private fun determineDeliveryMethod() {
        val contentSize = packed!!.size - LXMFConstants.LXMF_OVERHEAD

        // Default to DIRECT if not specified
        if (desiredMethod == null) {
            desiredMethod = DeliveryMethod.DIRECT
        }

        when (desiredMethod) {
            DeliveryMethod.OPPORTUNISTIC -> {
                if (contentSize > LXMFConstants.ENCRYPTED_PACKET_MAX_CONTENT) {
                    // Fall back to DIRECT for large messages
                    println("Opportunistic delivery requested but content too large ($contentSize bytes), falling back to DIRECT")
                    desiredMethod = DeliveryMethod.DIRECT
                    method = DeliveryMethod.DIRECT
                    representation =
                        if (contentSize <= LXMFConstants.LINK_PACKET_MAX_CONTENT) {
                            MessageRepresentation.PACKET
                        } else {
                            MessageRepresentation.RESOURCE
                        }
                } else {
                    method = DeliveryMethod.OPPORTUNISTIC
                    representation = MessageRepresentation.PACKET
                }
            }
            DeliveryMethod.DIRECT -> {
                method = DeliveryMethod.DIRECT
                representation =
                    if (contentSize <= LXMFConstants.LINK_PACKET_MAX_CONTENT) {
                        MessageRepresentation.PACKET
                    } else {
                        MessageRepresentation.RESOURCE
                    }
            }
            DeliveryMethod.PROPAGATED -> {
                method = DeliveryMethod.PROPAGATED
                // Propagated messages have additional encryption overhead
                representation = MessageRepresentation.RESOURCE // Conservative default
            }
            DeliveryMethod.PAPER -> {
                method = DeliveryMethod.PAPER
                representation = MessageRepresentation.PACKET
            }
            null -> {
                method = DeliveryMethod.DIRECT
                representation = MessageRepresentation.PACKET
            }
        }
    }

    /**
     * Pack payload into msgpack format.
     */
    private fun packPayload(
        timestamp: Double,
        title: String,
        content: String,
        fields: Map<Int, Any>,
        stamp: ByteArray?,
    ): ByteArray {
        val buffer = ByteArrayOutputStream()
        val packer = MessagePack.newDefaultPacker(buffer)

        // Pack as list with 4 or 5 elements
        val elementCount = if (stamp != null) 5 else 4
        packer.packArrayHeader(elementCount)

        // [0] timestamp as float64
        packer.packDouble(timestamp)

        // [1] title as bytes
        val titleBytes = title.toByteArray(Charsets.UTF_8)
        packer.packBinaryHeader(titleBytes.size)
        packer.writePayload(titleBytes)

        // [2] content as bytes
        val contentBytes = content.toByteArray(Charsets.UTF_8)
        packer.packBinaryHeader(contentBytes.size)
        packer.writePayload(contentBytes)

        // [3] fields as map
        packer.packMapHeader(fields.size)
        for ((key, value) in fields) {
            packer.packInt(key)
            packValue(packer, value)
        }

        // [4] stamp (optional)
        if (stamp != null) {
            packer.packBinaryHeader(stamp.size)
            packer.writePayload(stamp)
        }

        packer.close()
        return buffer.toByteArray()
    }

    /**
     * Pack a value into msgpack format (recursive for nested structures).
     */
    private fun packValue(
        packer: org.msgpack.core.MessagePacker,
        value: Any,
    ) {
        when (value) {
            is ByteArray -> {
                packer.packBinaryHeader(value.size)
                packer.writePayload(value)
            }
            is String -> packer.packString(value)
            is Int -> packer.packInt(value)
            is Long -> packer.packLong(value)
            is Double -> packer.packDouble(value)
            is Float -> packer.packFloat(value)
            is Boolean -> packer.packBoolean(value)
            is List<*> -> {
                packer.packArrayHeader(value.size)
                for (item in value) {
                    if (item != null) {
                        packValue(packer, item)
                    } else {
                        packer.packNil()
                    }
                }
            }
            is Map<*, *> -> {
                packer.packMapHeader(value.size)
                for ((k, v) in value) {
                    if (k != null) {
                        packValue(packer, k)
                    } else {
                        packer.packNil()
                    }
                    if (v != null) {
                        packValue(packer, v)
                    } else {
                        packer.packNil()
                    }
                }
            }
            else -> {
                // Default to string representation
                val str = value.toString().toByteArray(Charsets.UTF_8)
                packer.packBinaryHeader(str.size)
                packer.writePayload(str)
            }
        }
    }

    /**
     * Get title as bytes (UTF-8).
     */
    fun getTitleBytes(): ByteArray = title.toByteArray(Charsets.UTF_8)

    /**
     * Get content as bytes (UTF-8).
     */
    fun getContentBytes(): ByteArray = content.toByteArray(Charsets.UTF_8)

    /**
     * Set title from bytes.
     */
    fun setTitleFromBytes(bytes: ByteArray) {
        title = bytes.toString(Charsets.UTF_8)
    }

    /**
     * Set content from bytes.
     */
    fun setContentFromBytes(bytes: ByteArray) {
        content = bytes.toString(Charsets.UTF_8)
    }

    /**
     * Validate the stamp on this message.
     *
     * Matches Python LXMessage.validate_stamp() (lines 279-299):
     * 1. Ticket path: check if stamp == truncatedHash(ticket + messageId)
     * 2. Normal path: use LXStamper to validate proof-of-work
     *
     * @param targetCost Required stamp cost (leading zero bits)
     * @param tickets List of valid inbound tickets, or null
     * @return True if stamp is valid
     */
    fun validateStamp(
        targetCost: Int,
        tickets: List<ByteArray>? = null,
    ): Boolean {
        val msgHash = hash ?: return false
        val msgStamp = stamp

        stampChecked = true

        // Ticket path: check if stamp matches any ticket
        if (msgStamp != null && tickets != null) {
            for (ticket in tickets) {
                val ticketStamp = Hashes.truncatedHash(ticket + msgHash)
                if (msgStamp.contentEquals(ticketStamp)) {
                    stampValid = true
                    stampValue = LXMFConstants.COST_TICKET
                    return true
                }
            }
        }

        // Normal path: validate proof-of-work stamp
        if (msgStamp == null) {
            stampValid = false
            stampValue = null
            return false
        }

        val valid = LXStamper.validateStamp(msgStamp, msgHash, targetCost)
        stampValid = valid
        if (valid) {
            stampValue = LXStamper.getStampValue(msgStamp, msgHash)
        } else {
            stampValue = null
        }
        return valid
    }

    /**
     * Get or generate the stamp for this message.
     *
     * Matches Python LXMessage.get_stamp() (lines 304-332):
     * 1. Ticket path: if outboundTicket set, return truncatedHash(ticket + messageId)
     * 2. No cost: if stampCost null, return null
     * 3. Cached: if stamp already set, return it
     * 4. Generate: use LXStamper.generateStamp()
     *
     * @return Stamp bytes, or null if no stamp needed
     */
    suspend fun getStamp(): ByteArray? {
        val msgHash = hash ?: return null

        // Ticket path
        val ticket = outboundTicket
        if (ticket != null) {
            val ticketStamp = Hashes.truncatedHash(ticket + msgHash)
            stamp = ticketStamp
            stampCost = null
            return ticketStamp
        }

        // No cost required
        val cost = stampCost ?: return null

        // Cached stamp
        if (stamp != null) return stamp

        // Generate stamp
        val result = LXStamper.generateStampWithWorkblock(msgHash, cost)
        stamp = result.stamp
        return result.stamp
    }

    /**
     * Encode this message as a paper delivery URI (lxm://...).
     *
     * Matches Python LXMessage.as_uri() (lines 685-703):
     * 1. Pack message if not already packed
     * 2. Encrypt everything after dest hash for the destination
     * 3. Prepend dest hash to get paper_packed
     * 4. Base64url-encode without padding
     * 5. Prepend "lxm://"
     *
     * @return The lxm:// URI string
     */
    fun asUri(): String {
        if (packed == null) {
            pack()
        }

        val pp =
            paperPacked
                ?: throw IllegalStateException("Paper packing not done — call packForPaper() first or use PAPER delivery method")

        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(pp)
        return "${URI_SCHEMA}://$encoded"
    }

    /**
     * Pack message for PAPER delivery.
     *
     * Encrypts message content for the destination and prepends the destination hash.
     * Must be called before asUri().
     *
     * @throws IllegalStateException if destination is null or has no identity
     */
    fun packForPaper() {
        if (packed == null) {
            pack()
        }

        val dest =
            destination
                ?: throw IllegalStateException("Cannot pack for paper without destination")

        val packedData = packed!!
        val plainData = packedData.copyOfRange(LXMFConstants.DESTINATION_LENGTH, packedData.size)
        val encryptedData = dest.encrypt(plainData)
        paperPacked = packedData.copyOfRange(0, LXMFConstants.DESTINATION_LENGTH) + encryptedData

        method = DeliveryMethod.PAPER
        representation = MessageRepresentation.PACKET
    }

    // ===== Parity additions (Python LXMessage.py 1.1.0) =====

    /** Stamp generated for propagation-node delivery (Python `propagation_stamp`). */
    var propagationStamp: ByteArray? = null

    /** Value (leading zero bits) of the propagation stamp (Python `propagation_stamp_value`). */
    var propagationStampValue: Int? = null

    /** Whether the propagation stamp has been generated and validated. */
    var propagationStampValid: Boolean = false

    /** Target stamp cost announced by the selected propagation node. */
    var propagationTargetCost: Int? = null

    /** Whether this message supports compression on Resource transfer (Python `auto_compress`). */
    var autoCompress: Boolean = true

    /** Ratchet ID of the destination used for encrypted transfer (Python `ratchet_id`). */
    var ratchetId: ByteArray? = null

    /** Whether the source identity of an incoming message is blackholed. */
    var sourceBlackholed: Boolean = false

    /** Packed container bytes for propagation-node transfer (Python `propagation_packed`). */
    var propagationPacked: ByteArray? = null

    /** Delivery destination - may differ from [destination] when set via a router (Python `__delivery_destination`). */
    var deliveryDestination: Destination? = null
        private set

    /**
     * Set title from a String (Python `set_title_from_string`, LXMessage.py:193).
     * Kotlin stores title as String already; assignment is direct, matching
     * [setTitleFromBytes] which decodes before assigning.
     */
    fun setTitleFromString(titleString: String) {
        title = titleString
    }

    /**
     * Get title as a decoded String (Python `title_as_string`, LXMessage.py:199).
     * Identity accessor provided for API parity.
     */
    fun titleAsString(): String = title

    /**
     * Set content from a String (Python `set_content_from_string`, LXMessage.py:202).
     */
    fun setContentFromString(contentString: String) {
        content = contentString
    }

    /**
     * Get content as a decoded String (Python `content_as_string`, LXMessage.py:208).
     * Returns null if the stored content cannot round-trip through UTF-8
     * (unpaired surrogates), mirroring Python returning None on decode failure.
     */
    fun contentAsString(): String? {
        return try {
            val bytes = content.toByteArray(Charsets.UTF_8)
            val decoded = String(bytes, Charsets.UTF_8)
            if (decoded == content) decoded else null
        } catch (e: Exception) {
            println("$this could not decode message content as string: $e")
            null
        }
    }

    /**
     * Replace the fields dictionary (Python `set_fields`, LXMessage.py:215-219).
     * Accepts null and normalizes to an empty map. The existing map is mutated
     * in place so references obtained via [fields] observe the update.
     *
     * @throws IllegalArgumentException if fields is neither a Map nor null - the
     *         Python type check is enforced statically by Kotlin's type system here.
     */
    fun setFields(newFields: Map<Int, Any>?) {
        when (newFields) {
            null -> fields.clear()
            else -> {
                val typed: Map<Int, Any> = newFields
                fields.clear()
                fields.putAll(typed)
            }
        }
    }

    /**
     * Enforce Python's `set_destination` validation contract
     * (LXMessage.py:235-242): reject non-SINGLE destinations and reassignment.
     *
     * Deviation (port-deviations.md "set_destination/set_source validation-only"):
     * this port's `destination` is an immutable constructor property (`val`),
     * so this method validates but cannot rebind.
     *
     * @throws IllegalArgumentException if destination is not a SINGLE-type Destination
     * @throws IllegalStateException if the destination was already assigned
     */
    fun setDestination(destination: Destination?) {
        if (this.destination != null) {
            throw IllegalStateException("Cannot reassign destination on LXMessage")
        }
        if (destination == null || destination.type != DestinationType.SINGLE) {
            throw IllegalArgumentException("Invalid destination set on LXMessage")
        }
    }

    /**
     * Enforce Python's `set_source` validation contract (LXMessage.py:255-262).
     * See [setDestination] deviation note.
     *
     * @throws IllegalArgumentException if source is not a SINGLE-type Destination
     * @throws IllegalStateException if the source was already assigned
     */
    fun setSource(source: Destination?) {
        if (this.source != null) {
            throw IllegalStateException("Cannot reassign source on LXMessage")
        }
        if (source == null || source.type != DestinationType.SINGLE) {
            throw IllegalArgumentException("Invalid source set on LXMessage")
        }
    }

    /**
     * Set the delivery destination used by the router when handing off this
     * message (Python `set_delivery_destination`, LXMessage.py:264-265).
     */
    fun setDeliveryDestination(deliveryDestination: Destination?) {
        this.deliveryDestination = deliveryDestination
    }

    /**
     * Register the callback fired when delivery is confirmed
     * (Python `register_delivery_callback`, LXMessage.py:267-268).
     */
    fun registerDeliveryCallback(callback: ((LXMessage) -> Unit)?) {
        deliveryCallback = callback
    }

    /**
     * Register the callback fired when delivery definitively fails
     * (Python `register_failed_callback`, LXMessage.py:270-271).
     */
    fun registerFailedCallback(callback: ((LXMessage) -> Unit)?) {
        failedCallback = callback
    }

    /**
     * Get or generate the propagation stamp for this message
     * (Python `get_propagation_stamp`, LXMessage.py:329-353).
     *
     * Mirrors Python semantics:
     * 1. If a propagation stamp already exists, return it immediately.
     * 2. Record the node's target cost; raise if none configured.
     * 3. Pack the message if needed so a transient ID exists.
     * 4. Generate a proof-of-work stamp over the transient ID using the
     *    propagation-node workblock expansion rounds (WORKBLOCK_EXPAND_ROUNDS_PN).
     *
     * @param targetCost Required stamp cost announced by the propagation node
     * @return Stamp bytes, or null if generation did not produce a stamp
     * @throws IllegalArgumentException if targetCost is not configured
     */
    suspend fun getPropagationStamp(targetCost: Int?): ByteArray? {
        propagationStamp?.let { return it }

        propagationTargetCost = targetCost
        if (targetCost == null) {
            throw IllegalArgumentException(
                "Cannot generate propagation stamp without configured target propagation cost"
            )
        }

        // Python relies on pack()'s PROPAGATED branch to populate transient_id
        // (LXMessage.py:344 + 429-434); replicate via the dedicated helper so the
        // transient ID exists regardless of desired_method.
        if (transientId == null) {
            pack()
            if (computeTransientId() == null) {
                throw IllegalStateException(
                    "Cannot generate propagation stamp without a destination identity"
                )
            }
        }

        val result = LXStamper.generateStampWithWorkblock(
            messageId = transientId!!,
            stampCost = targetCost,
            expandRounds = LXStamper.WORKBLOCK_EXPAND_ROUNDS_PN,
        )
        return if (result.stamp != null) {
            propagationStamp = result.stamp
            propagationStampValue = result.value
            propagationStampValid = true
            result.stamp
        } else {
            null
        }
    }

    /**
     * Compute the transient ID for propagation transfer: full hash of
     * dest_hash + destination-encrypted packed payload
     * (Python `pack()` PROPAGATED branch, LXMessage.py:429-434).
     *
     * @return The computed transient ID, also stored in [transientId]; null
     *         when no destination identity is available for encryption
     */
    fun computeTransientId(): ByteArray? {
        val dest = destination ?: return null
        if (packed == null) pack()
        val encryptedData =
            dest.encrypt(packed!!.copyOfRange(LXMFConstants.DESTINATION_LENGTH, packed!!.size))
        ratchetId = dest.latestRatchetId
        val lxmfData = packed!!.copyOfRange(0, LXMFConstants.DESTINATION_LENGTH) + encryptedData
        transientId = Hashes.fullHash(lxmfData)
        return transientId
    }

    /**
     * Pack this message into its propagation-node wire container:
     * `msgpack([timebase, [lxmf_data (+ propagation stamp)]])` where
     * `lxmf_data = dest_hash + pn_encrypted_data (+ propagation_stamp)`
     * (Python `pack()` PROPAGATED branch, LXMessage.py:426-444).
     *
     * Also determines PACKET vs RESOURCE representation from container size.
     *
     * @return Propagation-packed bytes, also stored in [propagationPacked];
     *         null when no destination identity is available
     */
    fun packPropagation(): ByteArray? {
        val dest = destination ?: return null
        if (packed == null) pack()

        var lxmfData =
            packed!!.copyOfRange(0, LXMFConstants.DESTINATION_LENGTH) +
                dest.encrypt(packed!!.copyOfRange(LXMFConstants.DESTINATION_LENGTH, packed!!.size))
        ratchetId = dest.latestRatchetId
        transientId = Hashes.fullHash(lxmfData)
        propagationStamp?.let { lxmfData += it }

        val buffer = ByteArrayOutputStream()
        MessagePack.newDefaultPacker(buffer).use { p ->
            p.packArrayHeader(2)
            p.packDouble(System.currentTimeMillis() / 1000.0)
            p.packArrayHeader(1)
            p.packBinaryHeader(lxmfData.size)
            p.writePayload(lxmfData)
        }

        propagationPacked = buffer.toByteArray()
        method = DeliveryMethod.PROPAGATED
        representation =
            if (propagationPacked!!.size <= LXMFConstants.LINK_PACKET_MAX_CONTENT) {
                MessageRepresentation.PACKET
            } else {
                MessageRepresentation.RESOURCE
            }
        return propagationPacked
    }

    /**
     * Determine whether the remote side supports compression by inspecting
     * the remembered announce app-data for this destination
     * (Python `determine_compression_support`, LXMessage.py:510-513).
     * Defaults to true when no app-data is known, mirroring Python.
     */
    fun determineCompressionSupport() {
        val appData = Identity.recallAppData(destinationHash)
        autoCompress = if (appData != null && appData.isNotEmpty()) {
            compressionSupportFromAppData(appData) ?: true
        } else {
            true
        }
    }

    /**
     * Parse the compression-support flag out of announce app-data
     * (Python `compression_support_from_app_data`, LXMF.py:187-203).
     *
     * Version 0.5.0+ announces are msgpack lists whose third element, when
     * present and itself a list, carries service flags; SF_COMPRESSION = 0x00.
     * Returns null when app-data encodes "unknown" (null/empty), mirroring
     * Python's None return.
     */
    fun compressionSupportFromAppData(appData: ByteArray?): Boolean? {
        if (appData == null || appData.isEmpty()) return null

        return try {
            val unpacker = MessagePack.newDefaultUnpacker(appData)
            val value = unpackValue(unpacker)
            unpacker.close()

            val peerData = value as? List<*>
            if (peerData != null) {
                if (peerData.size < 3) {
                    true
                } else {
                    val flags = peerData[2] as? List<*>
                    if (flags == null) {
                        true
                    } else {
                        flags.any { f ->
                            when (f) {
                                is Byte -> f.toInt() == LXMFConstants.SF_COMPRESSION
                                is Int -> f == LXMFConstants.SF_COMPRESSION
                                is Long -> f.toInt() == LXMFConstants.SF_COMPRESSION
                                else -> false
                            }
                        }
                    }
                }
            } else {
                true
            }
        } catch (e: Exception) {
            // Original announce format or undecodable data - compression supported
            true
        }
    }

    /**
     * Determine and annotate the transport encryption used for delivery based
     * on the resolved delivery method and destination type
     * (Python `determine_transport_encryption`, LXMessage.py:520-559).
     */
    fun determineTransportEncryption() {
        val type = deliveryDestination?.type ?: destination?.type
        when (method) {
            DeliveryMethod.OPPORTUNISTIC, DeliveryMethod.PAPER -> when (type) {
                DestinationType.SINGLE -> {
                    transportEncrypted = true
                    transportEncryption = LXMFConstants.ENCRYPTION_DESCRIPTION_EC
                }
                DestinationType.GROUP -> {
                    transportEncrypted = true
                    transportEncryption = LXMFConstants.ENCRYPTION_DESCRIPTION_AES
                }
                else -> {
                    transportEncrypted = false
                    transportEncryption = LXMFConstants.ENCRYPTION_DESCRIPTION_UNENCRYPTED
                }
            }
            DeliveryMethod.DIRECT -> {
                transportEncrypted = true
                transportEncryption = LXMFConstants.ENCRYPTION_DESCRIPTION_EC
            }
            DeliveryMethod.PROPAGATED -> when (type) {
                DestinationType.SINGLE -> {
                    transportEncrypted = true
                    transportEncryption = LXMFConstants.ENCRYPTION_DESCRIPTION_EC
                }
                DestinationType.GROUP -> {
                    transportEncrypted = true
                    transportEncryption = LXMFConstants.ENCRYPTION_DESCRIPTION_AES
                }
                else -> {
                    transportEncrypted = false
                    transportEncryption = LXMFConstants.ENCRYPTION_DESCRIPTION_UNENCRYPTED
                }
            }
            else -> {
                transportEncrypted = false
                transportEncryption = LXMFConstants.ENCRYPTION_DESCRIPTION_UNENCRYPTED
            }
        }
    }

    /**
     * Send this message over its established delivery path
     * (Python `send`, LXMessage.py:463-508).
     *
     * Performs the pre-send annotations Python's `send()` makes - transport
     * encryption determination and compression-support determination - then
     * delegates packet/resource synthesis to the router-owned send hook wired
     * by `LXMRouter` at registration time.
     *
     * Deviation (see port-deviations.md "LXMessage.send() delegates to LXMRouter"):
     * direct Packet/Resource synthesis lives in `LXMRouter.sendViaLink` /
     * opportunistic / propagation paths in this port. Without a registered hook,
     * the message is marked FAILED and the failed callback fires instead of
     * crashing on a missing delivery destination.
     */
    fun send(): Boolean {
        determineTransportEncryption()
        determineCompressionSupport()

        val hook = routerSendHook
        return if (hook != null) {
            hook(this)
        } else {
            state = MessageState.FAILED
            failedCallback?.invoke(this)
            false
        }
    }

    /** Internal hook wired by `LXMRouter` at registration time; null until then. */
    internal var routerSendHook: ((LXMessage) -> Boolean)? = null

    /**
     * Serialize this message into a msgpack "container" suitable for persisting
     * to disk (Python `packed_container`, LXMessage.py:660-672):
     * `{state, lxmf_bytes, transport_encrypted, transport_encryption, method}`.
     */
    fun packedContainer(): ByteArray {
        if (packed == null) {
            pack()
        }

        val buffer = ByteArrayOutputStream()
        MessagePack.newDefaultPacker(buffer).use { packer ->
            packer.packMapHeader(5)
            packer.packString("state")
            packer.packInt(state.value)
            packer.packString("lxmf_bytes")
            val p = packed!!
            packer.packBinaryHeader(p.size)
            packer.writePayload(p)
            packer.packString("transport_encrypted")
            packer.packBoolean(transportEncrypted)
            packer.packString("transport_encryption")
            val enc = transportEncryption
            if (enc != null) packer.packString(enc) else packer.packNil()
            packer.packString("method")
            val m = method
            if (m != null) packer.packInt(m.value) else packer.packNil()
        }
        return buffer.toByteArray()
    }

    /**
     * Atomically write this message's [packedContainer] to a directory named
     * by the full message hash (Python `write_to_directory`, LXMessage.py:674-696).
     * Writes to a temp file first and renames atomically, cleaning up on failure.
     *
     * @return Path of the written file, or null on failure
     */
    fun writeToDirectory(directoryPath: String): String? {
        if (hash == null) {
            println("$this cannot be written to directory before being packed")
            return null
        }

        val fileName = hash!!.toHexString()
        val filePath = "$directoryPath/$fileName"
        val tmpPath =
            "$filePath.tmp.${System.currentTimeMillis()}." +
                ByteArray(8).also { java.security.SecureRandom().nextBytes(it) }.toHexString()

        return try {
            java.nio.file.Files.createDirectories(java.nio.file.Path.of(directoryPath))
            java.nio.file.Files.write(java.nio.file.Path.of(tmpPath), packedContainer())
            java.nio.file.Files.move(
                java.nio.file.Path.of(tmpPath),
                java.nio.file.Path.of(filePath),
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
            )
            filePath
        } catch (e: Exception) {
            try {
                java.nio.file.Files.deleteIfExists(java.nio.file.Path.of(tmpPath))
            } catch (_: Exception) {}
            println(
                "Error while writing LXMF message to file \"$filePath\". " +
                    "The contained exception was: $e"
            )
            null
        }
    }

    /**
     * Encode this message as a QR code image (Python `as_qr`, LXMessage.py:718-744).
     *
     * Requires a QR-code encoder on the classpath. The JVM core deliberately does
     * NOT bundle a QR library - callers supply their own renderer using [asUri]
     * output as the QR payload, matching Python where `qrcode` is optional and
     * `as_qr()` returns None without it.
     *
     * @return Null always in core; mirrors Python's missing-module branch.
     * @throws IllegalStateException if the message has no paper packing
     */
    fun asQr(): String? {
        if (paperPacked == null) {
            throw IllegalStateException(
                "Attempt to represent LXM with non-paper delivery method as QR-code"
            )
        }
        println(
            "Generating QR-code representations of LXMs requires a \"qrcode\" renderer. " +
                "Use asUri() output as the QR payload."
        )
        return null
    }

    override fun toString(): String {
        val hashStr = hash?.toHexString()?.take(12) ?: "unpacked"
        return "<LXMessage $hashStr>"
    }

    companion object {
        /** URI schema prefix */
        const val URI_SCHEMA = "lxm"

        /**
         * Create a new outbound LXMF message.
         *
         * @param destination The destination to send to
         * @param source The source destination (sender)
         * @param content Message content
         * @param title Message title (default empty)
         * @param fields Extended fields (default empty)
         * @param desiredMethod Desired delivery method (default DIRECT)
         * @return New LXMessage instance
         */
        fun create(
            destination: Destination,
            source: Destination,
            content: String,
            title: String = "",
            fields: MutableMap<Int, Any> = mutableMapOf(),
            desiredMethod: DeliveryMethod? = DeliveryMethod.DIRECT,
        ): LXMessage =
            LXMessage(
                destination = destination,
                source = source,
                destinationHash = destination.hash,
                sourceHash = source.hash,
                title = title,
                content = content,
                fields = fields,
                desiredMethod = desiredMethod,
            )

        /**
         * Unpack an LXMF message from wire format bytes.
         *
         * Wire format:
         * ```
         * [0:16]   Destination hash
         * [16:32]  Source hash
         * [32:96]  Signature
         * [96:]    Msgpack payload
         * ```
         *
         * @param lxmfBytes The packed message bytes
         * @param originalMethod The original delivery method (optional)
         * @return Unpacked LXMessage, or null if unpacking fails
         */
        fun unpackFromBytes(
            lxmfBytes: ByteArray,
            originalMethod: DeliveryMethod? = null,
        ): LXMessage? {
            try {
                // Minimum size: dest_hash (16) + source_hash (16) + signature (64) + some payload
                val minHeaderSize = 2 * LXMFConstants.DESTINATION_LENGTH + LXMFConstants.SIGNATURE_LENGTH
                if (lxmfBytes.size <= minHeaderSize) {
                    println("LXMF message too small: ${lxmfBytes.size} bytes (need > $minHeaderSize)")
                    return null
                }

                // Extract fixed-length fields
                val destinationHash = lxmfBytes.copyOfRange(0, LXMFConstants.DESTINATION_LENGTH)
                val sourceHash =
                    lxmfBytes.copyOfRange(
                        LXMFConstants.DESTINATION_LENGTH,
                        2 * LXMFConstants.DESTINATION_LENGTH,
                    )
                val signature =
                    lxmfBytes.copyOfRange(
                        2 * LXMFConstants.DESTINATION_LENGTH,
                        2 * LXMFConstants.DESTINATION_LENGTH + LXMFConstants.SIGNATURE_LENGTH,
                    )
                val packedPayload =
                    lxmfBytes.copyOfRange(
                        2 * LXMFConstants.DESTINATION_LENGTH + LXMFConstants.SIGNATURE_LENGTH,
                        lxmfBytes.size,
                    )

                // Unpack msgpack payload
                val unpacker = MessagePack.newDefaultUnpacker(packedPayload)
                val arraySize = unpacker.unpackArrayHeader()

                if (arraySize < 4) {
                    println("Invalid LXMF payload: expected at least 4 elements, got $arraySize")
                    return null
                }

                // [0] timestamp
                val timestamp = unpacker.unpackDouble()

                // [1] title
                val titleLen = unpacker.unpackBinaryHeader()
                val titleBytes = ByteArray(titleLen)
                unpacker.readPayload(titleBytes)

                // [2] content
                val contentLen = unpacker.unpackBinaryHeader()
                val contentBytes = ByteArray(contentLen)
                unpacker.readPayload(contentBytes)

                // [3] fields — may be msgpack Nil (interop: iOS LXMF and python's
                // `set_fields(None)` both produce Nil here; python tolerates this on
                // unpack via LXMessage.py:755 + set_fields() at LXMessage.py:220-224
                // which accepts None and normalizes to {}). Track wire encoding so
                // we can repack identically when a stamp is present.
                // tryUnpackNil() peek-and-consumes in one call; if it returns true the
                // Nil byte is already consumed so no follow-up unpackNil() is needed.
                val fieldsWasNil = unpacker.tryUnpackNil()
                val fields =
                    if (fieldsWasNil) {
                        mutableMapOf()
                    } else {
                        unpackFields(unpacker)
                    }

                // [4] stamp (optional)
                val stamp: ByteArray? =
                    if (arraySize > 4) {
                        val stampLen = unpacker.unpackBinaryHeader()
                        val stampBytes = ByteArray(stampLen)
                        unpacker.readPayload(stampBytes)
                        stampBytes
                    } else {
                        null
                    }

                unpacker.close()

                // Mirror python LXMessage.py:742-747: only re-pack to strip the stamp.
                // For stampless messages use the original packedPayload bytes directly —
                // any msgpack encoding round-trip risks a hash mismatch (e.g. empty fields
                // encoded as Nil 0xc0 vs empty Map 0x80). With a stamp present, repack
                // preserving the original fields encoding (Nil if it was Nil on the wire).
                val payloadWithoutStamp =
                    if (stamp == null) {
                        packedPayload
                    } else {
                        repackPayload(timestamp, titleBytes, contentBytes, fields, fieldsWasNil)
                    }

                // Build hashed part
                val hashedPart = destinationHash + sourceHash + payloadWithoutStamp

                // Compute message hash
                val messageHash = Hashes.fullHash(hashedPart)

                // Build signed part
                val signedPart = hashedPart + messageHash

                // Try to recall identities
                val destinationIdentity = Identity.recall(destinationHash)
                val sourceIdentity = Identity.recall(sourceHash)

                // Create destinations if identities are known
                val destination =
                    if (destinationIdentity != null) {
                        // Note: We'd need to create a destination here, but for incoming
                        // messages we typically don't need the full destination object
                        null
                    } else {
                        null
                    }

                val source =
                    if (sourceIdentity != null) {
                        null
                    } else {
                        null
                    }

                // Create message
                val message =
                    LXMessage(
                        destination = destination,
                        source = source,
                        destinationHash = destinationHash,
                        sourceHash = sourceHash,
                        title = titleBytes.toString(Charsets.UTF_8),
                        content = contentBytes.toString(Charsets.UTF_8),
                        fields = fields,
                        desiredMethod = originalMethod,
                    )

                message.hash = messageHash
                message.signature = signature
                message.stamp = stamp
                message.incoming = true
                message.timestamp = timestamp
                message.packed = lxmfBytes

                // Validate signature if source identity is known
                if (sourceIdentity != null) {
                    try {
                        if (sourceIdentity.validate(signature, signedPart)) {
                            message.signatureValidated = true
                        } else {
                            message.signatureValidated = false
                            message.unverifiedReason = UnverifiedReason.SIGNATURE_INVALID
                        }
                    } catch (e: Exception) {
                        message.signatureValidated = false
                        println("Error validating LXMF signature: ${e.message}")
                    }
                } else {
                    message.signatureValidated = false
                    message.unverifiedReason = UnverifiedReason.SOURCE_UNKNOWN
                    println("Cannot validate LXMF signature: source identity unknown")
                }

                return message
            } catch (e: Exception) {
                println("Error unpacking LXMF message: ${e.message}")
                e.printStackTrace()
                return null
            }
        }

        /**
         * Unpack fields map from msgpack.
         */
        private fun unpackFields(unpacker: org.msgpack.core.MessageUnpacker): MutableMap<Int, Any> {
            val fields = mutableMapOf<Int, Any>()
            val mapSize = unpacker.unpackMapHeader()

            repeat(mapSize) {
                val key = unpacker.unpackInt()
                val value = unpackValue(unpacker)
                if (value != null) {
                    fields[key] = value
                }
            }

            return fields
        }

        /**
         * Unpack a value from msgpack.
         */
        private fun unpackValue(unpacker: org.msgpack.core.MessageUnpacker): Any? {
            val format = unpacker.nextFormat
            val valueType = format.valueType
            return when (valueType.name) {
                "NIL" -> {
                    unpacker.unpackNil()
                    null
                }
                "BOOLEAN" -> unpacker.unpackBoolean()
                "INTEGER" -> unpacker.unpackLong()
                "FLOAT" -> unpacker.unpackDouble()
                "STRING" -> unpacker.unpackString()
                "BINARY" -> {
                    val len = unpacker.unpackBinaryHeader()
                    val bytes = ByteArray(len)
                    unpacker.readPayload(bytes)
                    bytes
                }
                "ARRAY" -> {
                    val size = unpacker.unpackArrayHeader()
                    val list = mutableListOf<Any?>()
                    repeat(size) {
                        list.add(unpackValue(unpacker))
                    }
                    list
                }
                "MAP" -> {
                    val size = unpacker.unpackMapHeader()
                    val map = mutableMapOf<Any?, Any?>()
                    repeat(size) {
                        val k = unpackValue(unpacker)
                        val v = unpackValue(unpacker)
                        map[k] = v
                    }
                    map
                }
                "EXTENSION" -> {
                    unpacker.skipValue()
                    null
                }
                else -> {
                    unpacker.skipValue()
                    null
                }
            }
        }

        /**
         * Repack payload without stamp for hash verification.
         *
         * [fieldsWasNil] preserves the original wire encoding for the fields
         * position. If the inbound payload encoded fields as msgpack Nil
         * (`0xc0`, what iOS LXMF and python's `msgpack.packb(None)` produce),
         * we must emit Nil here too — emitting an empty Map (`0x80`) instead
         * would change the byte representation and break the message hash.
         * Mirrors python `msgpack.packb(unpacked_payload)` round-trip
         * behavior at LXMessage.py:745, which preserves None as Nil.
         */
        private fun repackPayload(
            timestamp: Double,
            titleBytes: ByteArray,
            contentBytes: ByteArray,
            fields: Map<Int, Any>,
            fieldsWasNil: Boolean = false,
        ): ByteArray {
            val buffer = ByteArrayOutputStream()
            val packer = MessagePack.newDefaultPacker(buffer)

            // Pack as 4-element list (without stamp)
            packer.packArrayHeader(4)

            // [0] timestamp
            packer.packDouble(timestamp)

            // [1] title
            packer.packBinaryHeader(titleBytes.size)
            packer.writePayload(titleBytes)

            // [2] content
            packer.packBinaryHeader(contentBytes.size)
            packer.writePayload(contentBytes)

            // [3] fields — emit Nil if that's what the wire had, else Map
            if (fieldsWasNil && fields.isEmpty()) {
                packer.packNil()
            } else {
                packer.packMapHeader(fields.size)
                for ((key, value) in fields) {
                    packer.packInt(key)
                    repackValue(packer, value)
                }
            }

            packer.close()
            return buffer.toByteArray()
        }

        /**
         * Repack a value for hash verification.
         */
        private fun repackValue(
            packer: org.msgpack.core.MessagePacker,
            value: Any,
        ) {
            when (value) {
                is ByteArray -> {
                    packer.packBinaryHeader(value.size)
                    packer.writePayload(value)
                }
                is String -> packer.packString(value)
                is Int -> packer.packInt(value)
                is Long -> packer.packLong(value)
                is Double -> packer.packDouble(value)
                is Float -> packer.packFloat(value)
                is Boolean -> packer.packBoolean(value)
                is List<*> -> {
                    packer.packArrayHeader(value.size)
                    for (item in value) {
                        if (item != null) {
                            repackValue(packer, item)
                        } else {
                            packer.packNil()
                        }
                    }
                }
                is Map<*, *> -> {
                    packer.packMapHeader(value.size)
                    for ((k, v) in value) {
                        if (k != null) {
                            repackValue(packer, k)
                        } else {
                            packer.packNil()
                        }
                        if (v != null) {
                            repackValue(packer, v)
                        } else {
                            packer.packNil()
                        }
                    }
                }
                else -> packer.packString(value.toString())
            }
        }
    }
}
