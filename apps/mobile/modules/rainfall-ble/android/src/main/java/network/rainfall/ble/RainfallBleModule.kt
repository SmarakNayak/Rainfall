package network.rainfall.ble

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.*
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import javax.crypto.KeyAgreement

class RainfallBleModule : Module() {
  private val serviceUuid = UUID.fromString("8b198000-9941-4e40-9d98-76a1c55ba803")
  private val handshakeUuid = UUID.fromString("8b198001-9941-4e40-9d98-76a1c55ba803")
  private val confirmationUuid = UUID.fromString("8b198002-9941-4e40-9d98-76a1c55ba803")
  private val identityAlias = "rainfall-device-identity-v1"
  private val profilePreferences = "rainfall-profile"
  private val profileNameKey = "name"
  private var scanner: BluetoothLeScanner? = null
  private var advertiser: BluetoothLeAdvertiser? = null
  private var server: BluetoothGattServer? = null
  private var client: BluetoothGatt? = null
  private var pendingAdapter: BluetoothAdapter? = null
  private var confirmation: BluetoothGattCharacteristic? = null
  private val discovered = linkedMapOf<String, BluetoothDevice>()
  private var identity: KeyPair? = null
  private var ephemeral: KeyPair? = null
  private var handshake = byteArrayOf()
  private var peerIdentity = byteArrayOf()
  private var fingerprint = byteArrayOf()
  private var localConfirmed = false
  private var remoteConfirmed = false

  override fun definition() = ModuleDefinition {
    Name("RainfallBle")
    Events("onPeerFound", "onStateChanged", "onError")
    AsyncFunction("startDiscovery") { startDiscovery() }
    AsyncFunction("stopDiscovery") { stopDiscovery() }
    AsyncFunction("connectToPeer") { address: String -> connectToPeer(address) }
    AsyncFunction("confirmCeremony") { confirmCeremony() }
    AsyncFunction("getFriendCount") { friends().size }
    AsyncFunction("getProfileName") { profileName() }
    AsyncFunction("setProfileName") { name: String -> setProfileName(name) }
    OnDestroy { stopDiscovery() }
  }

  private val context: Context get() = requireNotNull(appContext.reactContext)
  private val manager: BluetoothManager
    get() = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager

  private fun permitted(): Boolean = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
    context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
  } else listOf(
    Manifest.permission.BLUETOOTH_SCAN,
    Manifest.permission.BLUETOOTH_ADVERTISE,
    Manifest.permission.BLUETOOTH_CONNECT,
  ).all { context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }

  @SuppressLint("MissingPermission")
  private fun startDiscovery() {
    if (!permitted()) error("Bluetooth permission has not been granted")
    val adapter = manager.adapter ?: error("Bluetooth is unavailable")
    if (!adapter.isEnabled) error("Bluetooth is turned off")
    if (!adapter.isMultipleAdvertisementSupported) error("BLE advertising is unsupported")
    check(profileName().isNotEmpty()) { "Set a Rainfall profile name before discovery" }
    stopDiscovery(false)
    resetSession()
    pendingAdapter = adapter
    identity = loadIdentity()
    ephemeral = KeyPairGenerator.getInstance("EC").run {
      initialize(ECGenParameterSpec("secp256r1")); generateKeyPair()
    }
    handshake = encodeHandshake(requireNotNull(identity), requireNotNull(ephemeral))
    registerService()
  }

  private fun loadIdentity(): KeyPair {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val saved = store.getEntry(identityAlias, null) as? KeyStore.PrivateKeyEntry
    if (saved != null) return KeyPair(saved.certificate.publicKey, saved.privateKey)
    return KeyPairGenerator.getInstance("EC", "AndroidKeyStore").run {
      initialize(android.security.keystore.KeyGenParameterSpec.Builder(
        identityAlias,
        android.security.keystore.KeyProperties.PURPOSE_SIGN or android.security.keystore.KeyProperties.PURPOSE_VERIFY,
      ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256).build())
      generateKeyPair()
    }
  }

  private fun profileName(): String = context
    .getSharedPreferences(profilePreferences, Context.MODE_PRIVATE)
    .getString(profileNameKey, "") ?: ""

  private fun setProfileName(value: String) {
    val name = value.trim()
    require(name.isNotEmpty()) { "Profile name cannot be empty" }
    require(name.codePointCount(0, name.length) <= 40) { "Profile name is too long" }
    context.getSharedPreferences(profilePreferences, Context.MODE_PRIVATE)
      .edit().putString(profileNameKey, name).apply()
  }

  private fun advertisedProfileName(): ByteArray {
    val output = StringBuilder()
    val name = profileName()
    var offset = 0
    while (offset < name.length) {
      val codePoint = name.codePointAt(offset)
      val candidate = output.toString() + String(Character.toChars(codePoint))
      if (candidate.toByteArray(Charsets.UTF_8).size > 12) break
      output.appendCodePoint(codePoint)
      offset += Character.charCount(codePoint)
    }
    return output.toString().toByteArray(Charsets.UTF_8)
  }

  private fun encodeHandshake(id: KeyPair, eph: KeyPair): ByteArray {
    val publicEphemeral = eph.public.encoded
    val signature = Signature.getInstance("SHA256withECDSA").run {
      initSign(id.private); update(publicEphemeral); sign()
    }
    return ByteArrayOutputStream().also { buffer -> DataOutputStream(buffer).use { output ->
      output.writeByte(1)
      listOf(id.public.encoded, publicEphemeral, signature).forEach { field ->
        output.writeShort(field.size); output.write(field)
      }
    } }.toByteArray()
  }

  private data class Peer(val identity: ByteArray, val ephemeral: ByteArray)

  private fun decodeHandshake(value: ByteArray): Peer {
    val input = DataInputStream(ByteArrayInputStream(value))
    require(input.readUnsignedByte() == 1) { "Unsupported handshake version" }
    fun field(): ByteArray {
      val size = input.readUnsignedShort()
      require(size in 1..384 && size <= input.available()) { "Invalid handshake" }
      return ByteArray(size).also(input::readFully)
    }
    val id = field(); val eph = field(); val signature = field()
    require(input.available() == 0) { "Invalid handshake suffix" }
    val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(id))
    require(Signature.getInstance("SHA256withECDSA").run {
      initVerify(key); update(eph); verify(signature)
    }) { "Peer signature is invalid" }
    return Peer(id, eph)
  }

  private fun establish(value: ByteArray) {
    val peer = decodeHandshake(value)
    val peerKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(peer.ephemeral))
    val secret = KeyAgreement.getInstance("ECDH").run {
      init(requireNotNull(ephemeral).private); doPhase(peerKey, true); generateSecret()
    }
    val ids = listOf(requireNotNull(identity).public.encoded, peer.identity).sortedWith(::compareBytes)
    fingerprint = MessageDigest.getInstance("SHA-256").digest(
      "rainfall-ceremony-v1".toByteArray() + secret + ids[0] + ids[1],
    )
    peerIdentity = peer.identity
    val code = fingerprint.take(6).joinToString(" · ") { "%02X".format(it) }
    state("verification-ready", mapOf("code" to code))
  }

  private fun compareBytes(a: ByteArray, b: ByteArray): Int {
    for (i in 0 until minOf(a.size, b.size)) {
      val result = (a[i].toInt() and 255).compareTo(b[i].toInt() and 255)
      if (result != 0) return result
    }
    return a.size.compareTo(b.size)
  }

  @SuppressLint("MissingPermission")
  private fun registerService() {
    val exchange = BluetoothGattCharacteristic(handshakeUuid,
      BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ)
    val approval = BluetoothGattCharacteristic(confirmationUuid,
      BluetoothGattCharacteristic.PROPERTY_WRITE, BluetoothGattCharacteristic.PERMISSION_WRITE)
    val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY).apply {
      addCharacteristic(exchange); addCharacteristic(approval)
    }
    server = manager.openGattServer(context, serverCallback) ?: error("Could not open GATT server")
    check(server?.addService(service) == true) { "Could not register Rainfall service" }
  }

  @SuppressLint("MissingPermission")
  private fun startRadio(adapter: BluetoothAdapter) {
    advertiser = adapter.bluetoothLeAdvertiser ?: error("BLE advertising is unavailable")
    advertiser?.startAdvertising(AdvertiseSettings.Builder()
      .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY).setConnectable(true)
      .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM).build(),
      AdvertiseData.Builder().addServiceUuid(ParcelUuid(serviceUuid)).build(),
      AdvertiseData.Builder()
        .addServiceData(ParcelUuid(serviceUuid), advertisedProfileName())
        .build(),
      advertiseCallback)
    scanner = adapter.bluetoothLeScanner ?: error("BLE scanning is unavailable")
    scanner?.startScan(listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(serviceUuid)).build()),
      ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), scanCallback)
    state("scanning")
  }

  @SuppressLint("MissingPermission")
  private fun connectToPeer(address: String) {
    check(client == null) { "A peer connection is already active" }
    val device = discovered[address] ?: error("That device is no longer nearby")
    state("connecting", mapOf("address" to address))
    client = device.connectGatt(context, false, clientCallback, BluetoothDevice.TRANSPORT_LE)
  }

  @SuppressLint("MissingPermission")
  @Suppress("DEPRECATION")
  private fun confirmCeremony() {
    check(fingerprint.isNotEmpty()) { "No ceremony is ready" }
    val gatt = client ?: error("Peer connection was lost")
    val target = confirmation ?: error("Confirmation channel is unavailable")
    localConfirmed = true
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      check(gatt.writeCharacteristic(target, fingerprint, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) ==
        BluetoothStatusCodes.SUCCESS) { "Could not send confirmation" }
    } else {
      target.value = fingerprint
      check(gatt.writeCharacteristic(target)) { "Could not send confirmation" }
    }
    state("waiting-for-friend")
    complete()
  }

  private fun receiveConfirmation(value: ByteArray): Boolean {
    if (fingerprint.isEmpty() || !MessageDigest.isEqual(fingerprint, value)) return false
    remoteConfirmed = true; complete(); return true
  }

  private fun complete() {
    if (!localConfirmed || !remoteConfirmed || peerIdentity.isEmpty()) return
    val id = MessageDigest.getInstance("SHA-256").digest(peerIdentity)
      .take(12).joinToString("") { "%02x".format(it) }
    context.getSharedPreferences("rainfall-friends", Context.MODE_PRIVATE)
      .edit().putLong(id, System.currentTimeMillis()).apply()
    state("friendship-created", mapOf("friendId" to id))
  }

  private fun friends() = context.getSharedPreferences("rainfall-friends", Context.MODE_PRIVATE).all.keys

  @SuppressLint("MissingPermission")
  private fun stopDiscovery(emit: Boolean = true) {
    scanner?.stopScan(scanCallback); advertiser?.stopAdvertising(advertiseCallback)
    client?.disconnect(); client?.close(); server?.close()
    scanner = null; advertiser = null; client = null; server = null
    pendingAdapter = null; confirmation = null; discovered.clear()
    if (emit) state("stopped")
  }

  private fun resetSession() {
    peerIdentity = byteArrayOf(); fingerprint = byteArrayOf()
    localConfirmed = false; remoteConfirmed = false
  }

  private fun state(name: String, extra: Map<String, Any> = emptyMap()) =
    sendEvent("onStateChanged", mapOf("state" to name) + extra)
  private fun fail(code: String, message: String) =
    sendEvent("onError", mapOf("code" to code, "message" to message))

  private val advertiseCallback = object : AdvertiseCallback() {
    override fun onStartSuccess(settings: AdvertiseSettings) = state("advertising")
    override fun onStartFailure(code: Int) = fail("advertise-$code", "BLE advertising failed")
  }

  private val scanCallback = object : ScanCallback() {
    @SuppressLint("MissingPermission")
    override fun onScanResult(type: Int, result: ScanResult) {
      val address = result.device.address
      discovered[address] = result.device
      val profileData = result.scanRecord?.getServiceData(ParcelUuid(serviceUuid))
      val name = profileData?.toString(Charsets.UTF_8)?.takeIf(String::isNotBlank) ?: "Rainfall user"
      sendEvent("onPeerFound", mapOf("address" to address, "name" to name, "rssi" to result.rssi))
    }
    override fun onScanFailed(code: Int) = fail("scan-$code", "BLE scanning failed")
  }

  private val clientCallback = object : BluetoothGattCallback() {
    @SuppressLint("MissingPermission")
    override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
      if (status != BluetoothGatt.GATT_SUCCESS) {
        fail("gatt-$status", "BLE connection failed"); gatt.close(); client = null
      } else if (newState == BluetoothProfile.STATE_CONNECTED) gatt.requestMtu(512)
    }
    @SuppressLint("MissingPermission")
    override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) { gatt.discoverServices() }
    @SuppressLint("MissingPermission")
    override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
      val service = gatt.getService(serviceUuid)
      val exchange = service?.getCharacteristic(handshakeUuid)
      confirmation = service?.getCharacteristic(confirmationUuid)
      if (status == BluetoothGatt.GATT_SUCCESS && exchange != null && confirmation != null)
        gatt.readCharacteristic(exchange)
      else fail("service-missing", "Rainfall service was not found")
    }
    @Deprecated("Android before API 33")
    override fun onCharacteristicRead(gatt: BluetoothGatt, item: BluetoothGattCharacteristic, status: Int) {
      @Suppress("DEPRECATION") val value = item.value
      if (status == BluetoothGatt.GATT_SUCCESS) handleHandshake(value)
      else fail("handshake-read-$status", "Could not read peer handshake")
    }
    override fun onCharacteristicRead(gatt: BluetoothGatt, item: BluetoothGattCharacteristic,
      value: ByteArray, status: Int) {
      if (status == BluetoothGatt.GATT_SUCCESS) handleHandshake(value)
      else fail("handshake-read-$status", "Could not read peer handshake")
    }
  }

  private fun handleHandshake(value: ByteArray) = try { establish(value) }
    catch (error: Exception) { fail("invalid-handshake", error.message ?: "Peer handshake failed") }

  private val serverCallback = object : BluetoothGattServerCallback() {
    override fun onServiceAdded(status: Int, service: BluetoothGattService) {
      if (status == BluetoothGatt.GATT_SUCCESS) pendingAdapter?.let(::startRadio)
      else fail("service-add-$status", "Could not register Rainfall service")
    }
    @SuppressLint("MissingPermission")
    override fun onCharacteristicReadRequest(device: BluetoothDevice, requestId: Int, offset: Int,
      item: BluetoothGattCharacteristic) {
      if (item.uuid != handshakeUuid) {
        server?.sendResponse(device, requestId, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, offset, null); return
      }
      val value = if (offset < handshake.size) handshake.copyOfRange(offset, handshake.size) else byteArrayOf()
      server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
    }
    @SuppressLint("MissingPermission")
    override fun onCharacteristicWriteRequest(device: BluetoothDevice, requestId: Int,
      item: BluetoothGattCharacteristic, preparedWrite: Boolean, responseNeeded: Boolean,
      offset: Int, value: ByteArray) {
      val accepted = item.uuid == confirmationUuid && offset == 0 && receiveConfirmation(value)
      if (responseNeeded) server?.sendResponse(device, requestId,
        if (accepted) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE, offset, null)
    }
  }
}
