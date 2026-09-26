/*
 * Native, retained-byte authentication for the two static EVM acquisitions.
 *
 * This translation unit deliberately has no path, environment, keychain,
 * network, or caller-policy inputs.  Its constants are the reviewed values in
 * scripts/native_evm_static_acquisition_assets.py (and its Medusa policy
 * module).  A caller must retain and hash the upstream objects before calling
 * these entry points and must rejoin the retained descriptors afterwards.
 */

import CryptoKit
import Foundation
import Security

private enum StaticAcquisitionFailure: Error {
    case invalid
}

private let medusaBundleSize = 10_584
private let medusaBundleSHA256 = "e7a277b17588fe02425a0cf4656f36d98f39eea9d4a7b0548e6617184238efb6"
private let medusaArchiveSize: UInt64 = 11_948_454
private let medusaArchiveSHA256 = "ddfe1517ae9028ef9fc331b00f5a6a9d5406f3fcd11a715d60c6b6fb3e4546d3"
private let medusaCertificateIdentity = "https://github.com/crytic/medusa/.github/workflows/ci.yml@refs/tags/v1.5.1"
private let medusaCertificateOIDCIssuer = "https://token.actions.githubusercontent.com"
private let medusaSourceCommit = "540a483b7a2a35b0a6d210aeb6ae6015aa7a0f62"
private let medusaTag = "refs/tags/v1.5.1"

private let solcIndexSize = 47_730
private let solcIndexSHA256 = "ee1a2b4811bd1225c220cd2342e2b49a58cbe18f5687f230f456c443b29497d6"
private let solcBinarySize: UInt64 = 15_434_456
private let solcBinarySHA256 = "d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef"
private let solcBinaryKeccak256 = "9d138fc8bb5c20b4aaaa3a868d16eb897584ce8536a5c3a466d718e47ccbafb7"
private let solcVersion = "0.8.26"
private let solcBuild = "commit.8a97fa7a"
private let solcLongVersion = "0.8.26+commit.8a97fa7a"
private let solcPath = "solc-linux-amd64-v0.8.26+commit.8a97fa7a"

private func hexadecimal(_ text: String) throws -> Data {
    guard text.utf8.count % 2 == 0 else { throw StaticAcquisitionFailure.invalid }
    var result = Data()
    result.reserveCapacity(text.utf8.count / 2)
    var index = text.startIndex
    while index != text.endIndex {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<next], radix: 16) else {
            throw StaticAcquisitionFailure.invalid
        }
        result.append(byte)
        index = next
    }
    return result
}

private func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

private func retainedData(_ pointer: UnsafeRawPointer?, _ size: Int) throws -> Data {
    guard size > 0, let pointer else { throw StaticAcquisitionFailure.invalid }
    return Data(bytes: pointer, count: size)
}

private func retainedDigest(_ pointer: UnsafePointer<UInt8>?) throws -> Data {
    guard let pointer else { throw StaticAcquisitionFailure.invalid }
    return Data(bytes: pointer, count: 32)
}

private func decodeJSON(_ raw: Data) throws -> [String: Any] {
    guard
        let value = try? JSONSerialization.jsonObject(with: raw, options: []),
        let object = value as? [String: Any]
    else { throw StaticAcquisitionFailure.invalid }
    return object
}

private func exactObject(
    _ value: Any?, keys: Set<String>
) throws -> [String: Any] {
    guard let object = value as? [String: Any], Set(object.keys) == keys else {
        throw StaticAcquisitionFailure.invalid
    }
    return object
}

private func exactArray(_ value: Any?) throws -> [Any] {
    guard let array = value as? [Any] else { throw StaticAcquisitionFailure.invalid }
    return array
}

private func exactString(_ value: Any?) throws -> String {
    guard let string = value as? String else { throw StaticAcquisitionFailure.invalid }
    return string
}

private func canonicalBase64(_ text: String) throws -> Data {
    guard
        !text.isEmpty,
        let decoded = Data(base64Encoded: text, options: []),
        decoded.base64EncodedString() == text
    else { throw StaticAcquisitionFailure.invalid }
    return decoded
}

private func canonicalDecimal(_ value: Any?) throws -> UInt64 {
    let text = try exactString(value)
    guard let number = UInt64(text), String(number) == text else {
        throw StaticAcquisitionFailure.invalid
    }
    return number
}

private struct DERTLV {
    let tag: UInt8
    let contentStart: Int
    let contentEnd: Int
}

private func readDER(_ data: Data, at cursor: inout Int, limit: Int) throws -> DERTLV {
    guard cursor >= 0, cursor < limit, limit <= data.count else {
        throw StaticAcquisitionFailure.invalid
    }
    let tag = data[cursor]
    cursor += 1
    guard tag & 0x1f != 0x1f, cursor < limit else {
        throw StaticAcquisitionFailure.invalid
    }
    let first = data[cursor]
    cursor += 1
    let length: Int
    if first & 0x80 == 0 {
        length = Int(first)
    } else {
        let octets = Int(first & 0x7f)
        guard octets > 0, octets <= 4, cursor + octets <= limit, data[cursor] != 0 else {
            throw StaticAcquisitionFailure.invalid
        }
        var decoded = 0
        for _ in 0..<octets {
            guard decoded <= (Int.max - Int(data[cursor])) / 256 else {
                throw StaticAcquisitionFailure.invalid
            }
            decoded = decoded * 256 + Int(data[cursor])
            cursor += 1
        }
        guard decoded >= 128 else { throw StaticAcquisitionFailure.invalid }
        length = decoded
    }
    guard length <= limit - cursor else { throw StaticAcquisitionFailure.invalid }
    let item = DERTLV(tag: tag, contentStart: cursor, contentEnd: cursor + length)
    cursor += length
    return item
}

private func derChildren(_ data: Data, _ parent: DERTLV) throws -> [DERTLV] {
    var cursor = parent.contentStart
    var children: [DERTLV] = []
    while cursor < parent.contentEnd {
        children.append(try readDER(data, at: &cursor, limit: parent.contentEnd))
    }
    guard cursor == parent.contentEnd else { throw StaticAcquisitionFailure.invalid }
    return children
}

private func derBytes(_ data: Data, _ item: DERTLV) -> Data {
    data.subdata(in: item.contentStart..<item.contentEnd)
}

private func derOID(_ data: Data, _ item: DERTLV) throws -> String {
    guard item.tag == 0x06 else { throw StaticAcquisitionFailure.invalid }
    let raw = derBytes(data, item)
    guard let first = raw.first else { throw StaticAcquisitionFailure.invalid }
    var components = [Int(first) / 40, Int(first) % 40]
    var value = 0
    var continuing = false
    for byte in raw.dropFirst() {
        if !continuing, byte == 0x80 { throw StaticAcquisitionFailure.invalid }
        guard value <= (Int.max - Int(byte & 0x7f)) / 128 else {
            throw StaticAcquisitionFailure.invalid
        }
        value = value * 128 + Int(byte & 0x7f)
        continuing = byte & 0x80 != 0
        if !continuing {
            components.append(value)
            value = 0
        }
    }
    guard !continuing else { throw StaticAcquisitionFailure.invalid }
    return components.map(String.init).joined(separator: ".")
}

private struct CertificateExtension {
    let critical: Bool
    let value: Data
}

private func certificateExtensions(_ der: Data) throws -> [String: CertificateExtension] {
    var cursor = 0
    let certificate = try readDER(der, at: &cursor, limit: der.count)
    guard certificate.tag == 0x30, cursor == der.count else {
        throw StaticAcquisitionFailure.invalid
    }
    let certificateParts = try derChildren(der, certificate)
    guard certificateParts.count == 3, certificateParts[0].tag == 0x30 else {
        throw StaticAcquisitionFailure.invalid
    }
    let tbsParts = try derChildren(der, certificateParts[0])
    let wrappers = tbsParts.filter { $0.tag == 0xa3 }
    guard wrappers.count == 1 else { throw StaticAcquisitionFailure.invalid }
    let wrapperParts = try derChildren(der, wrappers[0])
    guard wrapperParts.count == 1, wrapperParts[0].tag == 0x30 else {
        throw StaticAcquisitionFailure.invalid
    }
    var result: [String: CertificateExtension] = [:]
    for extensionItem in try derChildren(der, wrapperParts[0]) {
        guard extensionItem.tag == 0x30 else { throw StaticAcquisitionFailure.invalid }
        let parts = try derChildren(der, extensionItem)
        guard parts.count == 2 || parts.count == 3 else {
            throw StaticAcquisitionFailure.invalid
        }
        let oid = try derOID(der, parts[0])
        var valueIndex = 1
        var critical = false
        if parts.count == 3 {
            guard
                parts[1].tag == 0x01,
                derBytes(der, parts[1]) == Data([0xff])
            else { throw StaticAcquisitionFailure.invalid }
            critical = true
            valueIndex = 2
        }
        guard parts[valueIndex].tag == 0x04, result[oid] == nil else {
            throw StaticAcquisitionFailure.invalid
        }
        result[oid] = CertificateExtension(
            critical: critical, value: derBytes(der, parts[valueIndex])
        )
    }
    return result
}

private func validateCertificateProvenance(_ der: Data) throws -> SecKey {
    guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
        throw StaticAcquisitionFailure.invalid
    }
    let extensions = try certificateExtensions(der)
    guard
        let san = extensions["2.5.29.17"], san.critical,
        let issuer = extensions["1.3.6.1.4.1.57264.1.1"],
        let commit = extensions["1.3.6.1.4.1.57264.1.3"],
        let tag = extensions["1.3.6.1.4.1.57264.1.6"],
        !issuer.critical, !commit.critical, !tag.critical,
        String(data: issuer.value, encoding: .utf8) == medusaCertificateOIDCIssuer,
        String(data: commit.value, encoding: .utf8) == medusaSourceCommit,
        String(data: tag.value, encoding: .utf8) == medusaTag
    else { throw StaticAcquisitionFailure.invalid }

    var sanCursor = 0
    let names = try readDER(san.value, at: &sanCursor, limit: san.value.count)
    guard names.tag == 0x30, sanCursor == san.value.count else {
        throw StaticAcquisitionFailure.invalid
    }
    let generalNames = try derChildren(san.value, names)
    guard
        generalNames.count == 1,
        generalNames[0].tag == 0x86,
        String(data: derBytes(san.value, generalNames[0]), encoding: .utf8)
            == medusaCertificateIdentity,
        let key = SecCertificateCopyKey(certificate)
    else { throw StaticAcquisitionFailure.invalid }
    return key
}

private func certificateFromPEM(_ data: Data) throws -> Data {
    guard let text = String(data: data, encoding: .ascii) else {
        throw StaticAcquisitionFailure.invalid
    }
    let begin = "-----BEGIN CERTIFICATE-----\n"
    let end = "\n-----END CERTIFICATE-----\n"
    guard text.hasPrefix(begin), text.hasSuffix(end), !text.contains("\r") else {
        throw StaticAcquisitionFailure.invalid
    }
    let first = text.index(text.startIndex, offsetBy: begin.count)
    let last = text.index(text.endIndex, offsetBy: -end.count)
    let lines = text[first..<last].split(separator: "\n", omittingEmptySubsequences: false)
    guard !lines.isEmpty else { throw StaticAcquisitionFailure.invalid }
    for (index, line) in lines.enumerated() {
        guard !line.isEmpty, index == lines.count - 1 || line.count == 64 else {
            throw StaticAcquisitionFailure.invalid
        }
    }
    return try canonicalBase64(lines.joined())
}

private func merkleRoot(
    body: Data, proofHashes: [Any], leafIndex: UInt64, treeSize: UInt64
) throws -> Data {
    guard treeSize > 0, leafIndex < treeSize else {
        throw StaticAcquisitionFailure.invalid
    }
    var leafInput = Data([0x00])
    leafInput.append(body)
    var current = sha256(leafInput)
    var index = leafIndex
    var size = treeSize
    for encoded in proofHashes {
        let sibling = try canonicalBase64(try exactString(encoded))
        guard sibling.count == 32, size > 1 else {
            throw StaticAcquisitionFailure.invalid
        }
        var node = Data([0x01])
        if index & 1 == 1 || index == size - 1 {
            node.append(sibling)
            node.append(current)
            while index != 0, index & 1 == 0 {
                index /= 2
                size = size / 2 + size % 2
            }
        } else {
            node.append(current)
            node.append(sibling)
        }
        current = sha256(node)
        index /= 2
        size = size / 2 + size % 2
    }
    guard index == 0, size == 1 else { throw StaticAcquisitionFailure.invalid }
    return current
}

private func verifyMedusa(
    bundleRaw: Data, archiveDigest: Data, archiveSize: UInt64
) throws {
    guard
        bundleRaw.count == medusaBundleSize,
        sha256(bundleRaw) == (try hexadecimal(medusaBundleSHA256)),
        archiveSize == medusaArchiveSize,
        archiveDigest == (try hexadecimal(medusaArchiveSHA256))
    else { throw StaticAcquisitionFailure.invalid }

    let top = try decodeJSON(bundleRaw)
    guard Set(top.keys) == Set(["mediaType", "verificationMaterial", "messageSignature"]),
          !(try exactString(top["mediaType"])).isEmpty else {
        throw StaticAcquisitionFailure.invalid
    }
    let material = try exactObject(
        top["verificationMaterial"],
        keys: Set(["certificate", "tlogEntries", "timestampVerificationData"])
    )
    let certificateObject = try exactObject(material["certificate"], keys: Set(["rawBytes"]))
    let certificateDER = try canonicalBase64(try exactString(certificateObject["rawBytes"]))
    let publicKey = try validateCertificateProvenance(certificateDER)

    let messageSignature = try exactObject(
        top["messageSignature"], keys: Set(["messageDigest", "signature"])
    )
    let messageDigest = try exactObject(
        messageSignature["messageDigest"], keys: Set(["algorithm", "digest"])
    )
    guard
        try exactString(messageDigest["algorithm"]) == "SHA2_256",
        try canonicalBase64(try exactString(messageDigest["digest"])) == archiveDigest
    else { throw StaticAcquisitionFailure.invalid }
    let signature = try canonicalBase64(try exactString(messageSignature["signature"]))
    var signatureError: Unmanaged<CFError>?
    guard SecKeyVerifySignature(
        publicKey, .ecdsaSignatureDigestX962SHA256,
        archiveDigest as CFData, signature as CFData, &signatureError
    ) else { throw StaticAcquisitionFailure.invalid }

    let timestamps = try exactObject(
        material["timestampVerificationData"], keys: Set(["rfc3161Timestamps"])
    )
    let timestampRows = try exactArray(timestamps["rfc3161Timestamps"])
    guard timestampRows.count == 1 else { throw StaticAcquisitionFailure.invalid }
    let timestamp = try exactObject(timestampRows[0], keys: Set(["signedTimestamp"]))
    _ = try canonicalBase64(try exactString(timestamp["signedTimestamp"]))

    let logRows = try exactArray(material["tlogEntries"])
    guard logRows.count == 1 else { throw StaticAcquisitionFailure.invalid }
    let log = try exactObject(
        logRows[0],
        keys: Set([
            "canonicalizedBody", "inclusionPromise", "inclusionProof", "integratedTime",
            "kindVersion", "logId", "logIndex",
        ])
    )
    _ = try canonicalDecimal(log["integratedTime"])
    _ = try canonicalDecimal(log["logIndex"])
    let logID = try exactObject(log["logId"], keys: Set(["keyId"]))
    guard try canonicalBase64(try exactString(logID["keyId"])).count == 32 else {
        throw StaticAcquisitionFailure.invalid
    }
    let kindVersion = try exactObject(log["kindVersion"], keys: Set(["kind", "version"]))
    guard
        try exactString(kindVersion["kind"]) == "hashedrekord",
        try exactString(kindVersion["version"]) == "0.0.1"
    else { throw StaticAcquisitionFailure.invalid }
    let promise = try exactObject(log["inclusionPromise"], keys: Set(["signedEntryTimestamp"]))
    _ = try canonicalBase64(try exactString(promise["signedEntryTimestamp"]))

    let body = try canonicalBase64(try exactString(log["canonicalizedBody"]))
    let bodyObject = try decodeJSON(body)
    guard Set(bodyObject.keys) == Set(["apiVersion", "kind", "spec"]),
          try exactString(bodyObject["apiVersion"]) == "0.0.1",
          try exactString(bodyObject["kind"]) == "hashedrekord" else {
        throw StaticAcquisitionFailure.invalid
    }
    let spec = try exactObject(bodyObject["spec"], keys: Set(["data", "signature"]))
    let bodyData = try exactObject(spec["data"], keys: Set(["hash"]))
    let bodyHash = try exactObject(bodyData["hash"], keys: Set(["algorithm", "value"]))
    guard
        try exactString(bodyHash["algorithm"]) == "sha256",
        try exactString(bodyHash["value"]) == medusaArchiveSHA256
    else { throw StaticAcquisitionFailure.invalid }
    let bodySignature = try exactObject(
        spec["signature"], keys: Set(["content", "publicKey"])
    )
    guard
        try canonicalBase64(try exactString(bodySignature["content"])) == signature
    else { throw StaticAcquisitionFailure.invalid }
    let bodyPublicKey = try exactObject(bodySignature["publicKey"], keys: Set(["content"]))
    let pem = try canonicalBase64(try exactString(bodyPublicKey["content"]))
    guard try certificateFromPEM(pem) == certificateDER else {
        throw StaticAcquisitionFailure.invalid
    }

    let proof = try exactObject(
        log["inclusionProof"],
        keys: Set(["checkpoint", "hashes", "logIndex", "rootHash", "treeSize"])
    )
    let checkpoint = try exactObject(proof["checkpoint"], keys: Set(["envelope"]))
    let proofIndex = try canonicalDecimal(proof["logIndex"])
    let treeSize = try canonicalDecimal(proof["treeSize"])
    let hashes = try exactArray(proof["hashes"])
    let encodedRoot = try exactString(proof["rootHash"])
    let expectedRoot = try canonicalBase64(encodedRoot)
    let checkpointLines = try exactString(checkpoint["envelope"])
        .split(separator: "\n", omittingEmptySubsequences: false)
    guard
        expectedRoot.count == 32,
        checkpointLines.count == 6,
        !checkpointLines[0].isEmpty,
        checkpointLines[1] == Substring(String(treeSize)),
        checkpointLines[2] == Substring(encodedRoot),
        checkpointLines[3].isEmpty,
        !checkpointLines[4].isEmpty,
        checkpointLines[5].isEmpty,
        try merkleRoot(
            body: body, proofHashes: hashes, leafIndex: proofIndex, treeSize: treeSize
        ) == expectedRoot
    else { throw StaticAcquisitionFailure.invalid }
}

private func verifySolc(
    indexRaw: Data, binaryDigest: Data, binarySize: UInt64
) throws {
    guard
        indexRaw.count == solcIndexSize,
        sha256(indexRaw) == (try hexadecimal(solcIndexSHA256)),
        binaryDigest == (try hexadecimal(solcBinarySHA256)),
        binarySize == solcBinarySize
    else { throw StaticAcquisitionFailure.invalid }
    let top = try decodeJSON(indexRaw)
    guard Set(top.keys) == Set(["builds", "latestRelease", "releases"]),
          top["latestRelease"] is String else {
        throw StaticAcquisitionFailure.invalid
    }
    let builds = try exactArray(top["builds"])
    let objects = try builds.map {
        guard let object = $0 as? [String: Any] else {
            throw StaticAcquisitionFailure.invalid
        }
        return object
    }
    let versionMatches = objects.filter { ($0["version"] as? String) == solcVersion }
    let pathMatches = objects.filter { ($0["path"] as? String) == solcPath }
    guard versionMatches.count == 1, pathMatches.count == 1 else {
        throw StaticAcquisitionFailure.invalid
    }
    let selected = versionMatches[0]
    guard
        (selected["path"] as? String) == solcPath,
        Set(selected.keys) == Set([
            "build", "keccak256", "longVersion", "path", "sha256", "urls", "version",
        ]),
        try exactString(selected["build"]) == solcBuild,
        try exactString(selected["longVersion"]) == solcLongVersion,
        try exactString(selected["sha256"]) == "0x" + solcBinarySHA256,
        try exactString(selected["keccak256"]) == "0x" + solcBinaryKeccak256,
        let urls = selected["urls"] as? [String], !urls.isEmpty,
        urls.allSatisfy({ !$0.isEmpty })
    else { throw StaticAcquisitionFailure.invalid }
    guard let releases = top["releases"] as? [String: Any], !releases.isEmpty else {
        throw StaticAcquisitionFailure.invalid
    }
    guard try exactString(releases[solcVersion]) == solcPath else {
        throw StaticAcquisitionFailure.invalid
    }
}

@_cdecl("plamen_native_evm_medusa_sigstore_verify_v1")
public func plamenNativeEVMMedusaSigstoreVerifyV1(
    _ bundle: UnsafeRawPointer?,
    _ bundleSize: Int,
    _ archiveSHA256: UnsafePointer<UInt8>?,
    _ archiveSize: UInt64
) -> Int32 {
    do {
        let raw = try retainedData(bundle, bundleSize)
        let digest = try retainedDigest(archiveSHA256)
        try verifyMedusa(bundleRaw: raw, archiveDigest: digest, archiveSize: archiveSize)
        return 0
    } catch {
        return -1
    }
}

@_cdecl("plamen_native_evm_solc_provider_verify_v1")
public func plamenNativeEVMSolcProviderVerifyV1(
    _ indexJSON: UnsafeRawPointer?,
    _ indexSize: Int,
    _ binarySHA256: UnsafePointer<UInt8>?,
    _ binarySize: UInt64
) -> Int32 {
    do {
        let raw = try retainedData(indexJSON, indexSize)
        let digest = try retainedDigest(binarySHA256)
        try verifySolc(indexRaw: raw, binaryDigest: digest, binarySize: binarySize)
        return 0
    } catch {
        return -1
    }
}
