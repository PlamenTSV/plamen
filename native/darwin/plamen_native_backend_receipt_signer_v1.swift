import CoreFoundation
import CryptoKit
import Foundation

private final class PlamenBackendSigningAuthority {
    let privateKey: Curve25519.Signing.PrivateKey
    let publicKey: Data

    init() {
        privateKey = Curve25519.Signing.PrivateKey()
        publicKey = privateKey.publicKey.rawRepresentation
    }
}

private let unsignedFields: Set<String> = [
    "schema", "selector", "policy_schema", "policy_sha256",
    "resolved_version", "resolved_release", "registry", "upstream",
    "transport", "payload", "installed", "probes", "install",
]

private func hex(_ bytes: UnsafePointer<UInt8>, _ count: Int) -> String {
    var result = ""
    result.reserveCapacity(count * 2)
    for index in 0..<count {
        result += String(format: "%02x", bytes[index])
    }
    return result
}

private func canonical(_ value: Any) throws -> Data {
    guard JSONSerialization.isValidJSONObject(value) else {
        throw NSError(domain: "PlamenBackendSigner", code: 1)
    }
    return try JSONSerialization.data(
        withJSONObject: value,
        options: [.sortedKeys, .withoutEscapingSlashes]
    )
}

private func exactPositiveInteger(_ value: Any?) -> UInt64? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
    let result = number.uint64Value
    guard result > 0, number.stringValue == String(result) else { return nil }
    return result
}

private func exactASCII(_ value: Any?, maximum: Int) -> String? {
    guard let string = value as? String,
          !string.isEmpty, string.utf8.count < maximum,
          string.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
        return nil
    }
    return string
}

private func isSemver(_ value: String) -> Bool {
    let pattern = #"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$"#
    return value.range(of: pattern, options: .regularExpression) != nil
}

@_cdecl("plamen_native_backend_crypto_create_v1")
public func plamenNativeBackendCryptoCreateV1(
    _ contextOutput: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ publicOutput: UnsafeMutablePointer<UInt8>?,
    _ publicCapacity: Int
) -> Int32 {
    guard let contextOutput, let publicOutput, publicCapacity == 32 else {
        return -1
    }
    contextOutput.pointee = nil
    let authority = PlamenBackendSigningAuthority()
    guard authority.publicKey.count == 32 else { return -1 }
    authority.publicKey.copyBytes(to: publicOutput, count: 32)
    contextOutput.pointee = Unmanaged.passRetained(authority).toOpaque()
    return 0
}

@_cdecl("plamen_native_backend_crypto_sign_receipt_v1")
public func plamenNativeBackendCryptoSignReceiptV1(
    _ opaque: UnsafeMutableRawPointer?,
    _ role: UInt16,
    _ unsignedBytes: UnsafePointer<UInt8>?,
    _ unsignedSize: Int,
    _ payloadSHA256: UnsafePointer<UInt8>?,
    _ payloadSize: UInt64,
    _ manifestSHA256: UnsafePointer<UInt8>?,
    _ manifestSize: UInt64,
    _ policySHA256: UnsafePointer<UInt8>?,
    _ output: UnsafeMutablePointer<UInt8>?,
    _ outputCapacity: Int,
    _ outputSize: UnsafeMutablePointer<Int>?,
    _ resolvedVersion: UnsafeMutablePointer<CChar>?,
    _ resolvedVersionCapacity: Int
) -> Int32 {
    guard let opaque, let unsignedBytes, unsignedSize > 1,
          let payloadSHA256, payloadSize > 0,
          let manifestSHA256, manifestSize > 0, let policySHA256,
          let output, outputCapacity > unsignedSize,
          let outputSize, let resolvedVersion, resolvedVersionCapacity == 128,
          role == 5 || role == 6 else { return -1 }
    outputSize.pointee = 0
    memset(resolvedVersion, 0, resolvedVersionCapacity)
    do {
        let raw = Data(bytes: unsignedBytes, count: unsignedSize)
        let object = try JSONSerialization.jsonObject(with: raw)
        guard var receipt = object as? [String: Any],
              Set(receipt.keys) == unsignedFields,
              try canonical(receipt) == raw else { return -1 }
        let selector = role == 5 ? "codex" : "claude"
        let expectedSchema = "plamen.native-backend-latest-acquisition-receipt.v1"
        let policyHex = hex(policySHA256, 32)
        guard receipt["schema"] as? String == expectedSchema,
              receipt["selector"] as? String == selector,
              receipt["policy_schema"] as? String ==
                "plamen.native-backend-acquisition.v2",
              receipt["policy_sha256"] as? String == policyHex,
              let version = exactASCII(
                receipt["resolved_version"], maximum: resolvedVersionCapacity),
              isSemver(version),
              let payload = receipt["payload"] as? [String: Any],
              exactPositiveInteger(payload["size"]) == payloadSize,
              payload["sha256"] as? String == hex(payloadSHA256, 32),
              let install = receipt["install"] as? [String: Any],
              exactPositiveInteger(install["source_manifest_size"]) == manifestSize,
              install["source_manifest_sha256"] as? String ==
                hex(manifestSHA256, 32) else { return -1 }
        let authority = Unmanaged<PlamenBackendSigningAuthority>
            .fromOpaque(opaque).takeUnretainedValue()
        let signature = try authority.privateKey.signature(for: raw)
        guard signature.count == 64 else { return -1 }
        let keyID = SHA256.hash(data: authority.publicKey)
            .map { String(format: "%02x", $0) }.joined()
        receipt["authentication"] = [
            "scheme": "ed25519", "key_id": keyID,
            "signature": signature.map { String(format: "%02x", $0) }.joined(),
        ]
        let candidate = try canonical(receipt)
        receipt["receipt_sha256"] = SHA256.hash(data: candidate)
            .map { String(format: "%02x", $0) }.joined()
        let signed = try canonical(receipt)
        guard signed.count <= outputCapacity else { return -1 }
        signed.copyBytes(to: output, count: signed.count)
        outputSize.pointee = signed.count
        _ = version.utf8CString.withUnsafeBytes { versionBytes in
            memcpy(resolvedVersion, versionBytes.baseAddress!, versionBytes.count)
        }
        return 0
    } catch {
        return -1
    }
}

@_cdecl("plamen_native_backend_crypto_dispose_v1")
public func plamenNativeBackendCryptoDisposeV1(_ opaque: UnsafeMutableRawPointer?) {
    guard let opaque else { return }
    Unmanaged<PlamenBackendSigningAuthority>.fromOpaque(opaque).release()
}
