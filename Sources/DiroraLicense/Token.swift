import Crypto
import Foundation

/// Stable error codes of the licence API.
public enum ErrorCode {
    public static let invalidRequest = "invalid_request"
    public static let tenantNotFound = "tenant_not_found"
    public static let licenseNotFound = "license_not_found"
    public static let keyReplaced = "key_replaced"
    public static let licenseBlocked = "license_blocked"
    public static let activationLimit = "activation_limit_reached"
    public static let activationCodeRequired = "activation_code_required"
    public static let activationCodeInvalid = "activation_code_invalid"
    public static let machineNotActivated = "machine_not_activated"
    public static let releaseNotFound = "release_not_found"
    public static let updateNotCovered = "update_not_covered"
    public static let fileUnavailable = "file_unavailable"
    public static let virtualMachine = "virtual_machine_not_allowed"
    public static let noSeatAvailable = "no_seat_available"
    public static let trialNotAvailable = "trial_not_available"
    public static let trialLimit = "trial_limit_reached"
    public static let signInRequired = "sign_in_required"
    public static let deviceCodeInvalid = "device_code_invalid"
    public static let noSeat = "no_seat"
    public static let usageLimit = "usage_limit_reached"
    public static let meterNotFound = "meter_not_found"
    public static let rateLimited = "rate_limited"
}

public enum LicenseError: Error, Equatable {
    /// A refusal from the licence API: `code` is stable, `message` English.
    case api(status: Int, code: String, message: String)
    /// The answer was not signed by your shop's key, or not for this request.
    case badSignature
    /// A downloaded file does not match its signed SHA-256.
    case checksumMismatch
    /// The person did not allow the sign-in ("denied"), or it expired ("expired").
    case signIn(String)
    /// Network failure (offline, timeout…).
    case transport(String)
    case config(String)

    /// The stable API code, if this is a refusal.
    public var code: String? {
        if case let .api(_, code, _) = self { return code }
        return nil
    }
}

/// A signed answer or document: base64 payload bytes and their Ed25519
/// signature; `kid` names the key. Only the verified payload is trusted.
public struct SignedToken: Codable, Equatable {
    public let alg: String
    public let payload: String
    public let signature: String
    public let kid: String?

    public init(alg: String, payload: String, signature: String, kid: String? = nil) {
        self.alg = alg
        self.payload = payload
        self.signature = signature
        self.kid = kid
    }
}

/// A verified licence answer.
public struct Token: Decodable {
    public var version: Int = 0
    public var licenseId = ""
    public var productId = ""
    public var tenantId = ""
    public var machineFingerprint = ""
    /// valid | lapsed | blocked
    public var status = ""
    public var reason: String?
    public var licenseType = ""
    public var expiresAt: String?
    public var updatesPolicy = ""
    public var updatesUntil: String?
    public var supportPolicy = ""
    public var supportUntil: String?
    public var features: [String] = []
    public var issuedAt = ""
    public var checkinAfter = ""
    public var validUntil = ""
    public var nonce: String?
    /// node_locked, or floating: a lease — renew (check) and release on exit.
    public var licenseModel: String?
    /// key | user (signed in)
    public var auth: String?
    public var seats = 0
    /// Activated with a licence file; no check-ins.
    public var offline = false

    enum CodingKeys: String, CodingKey {
        case version = "v", licenseId = "license_id", productId = "product_id", tenantId = "tenant_id"
        case machineFingerprint = "machine_fingerprint", status, reason, licenseType = "license_type"
        case expiresAt = "expires_at", updatesPolicy = "updates_policy", updatesUntil = "updates_until"
        case supportPolicy = "support_policy", supportUntil = "support_until", features
        case issuedAt = "issued_at", checkinAfter = "checkin_after", validUntil = "valid_until", nonce
        case licenseModel = "license_model", auth, seats, offline
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 0
        licenseId = try c.decodeIfPresent(String.self, forKey: .licenseId) ?? ""
        productId = try c.decodeIfPresent(String.self, forKey: .productId) ?? ""
        tenantId = try c.decodeIfPresent(String.self, forKey: .tenantId) ?? ""
        machineFingerprint = try c.decodeIfPresent(String.self, forKey: .machineFingerprint) ?? ""
        status = try c.decodeIfPresent(String.self, forKey: .status) ?? ""
        reason = try c.decodeIfPresent(String.self, forKey: .reason)
        licenseType = try c.decodeIfPresent(String.self, forKey: .licenseType) ?? ""
        expiresAt = try c.decodeIfPresent(String.self, forKey: .expiresAt)
        updatesPolicy = try c.decodeIfPresent(String.self, forKey: .updatesPolicy) ?? ""
        updatesUntil = try c.decodeIfPresent(String.self, forKey: .updatesUntil)
        supportPolicy = try c.decodeIfPresent(String.self, forKey: .supportPolicy) ?? ""
        supportUntil = try c.decodeIfPresent(String.self, forKey: .supportUntil)
        features = try c.decodeIfPresent([String].self, forKey: .features) ?? []
        issuedAt = try c.decodeIfPresent(String.self, forKey: .issuedAt) ?? ""
        checkinAfter = try c.decodeIfPresent(String.self, forKey: .checkinAfter) ?? ""
        validUntil = try c.decodeIfPresent(String.self, forKey: .validUntil) ?? ""
        nonce = try c.decodeIfPresent(String.self, forKey: .nonce)
        licenseModel = try c.decodeIfPresent(String.self, forKey: .licenseModel)
        auth = try c.decodeIfPresent(String.self, forKey: .auth)
        seats = try c.decodeIfPresent(Int.self, forKey: .seats) ?? 0
        offline = try c.decodeIfPresent(Bool.self, forKey: .offline) ?? false
    }

    static func parse(_ s: String?) -> Date? {
        guard let s, !s.isEmpty else { return nil }
        let f = ISO8601DateFormatter()
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.date(from: s)
    }

    public func hasFeature(_ name: String) -> Bool { features.contains(name) }

    public var isTrial: Bool { licenseType == "trial" }

    public func trialDaysLeft(now: Date) -> Int {
        guard isTrial, let end = Token.parse(expiresAt), now < end else { return 0 }
        return Int(end.timeIntervalSince(now) / 86400) + 1
    }

    /// Whether a build released at `buildDate` is within the updates period.
    public func coversBuild(_ buildDate: Date) -> Bool {
        guard updatesPolicy == "term" else { return true }
        guard let until = Token.parse(updatesUntil) else { return false }
        return buildDate <= until
    }

    /// The gate before the software starts working.
    public func canRun(fingerprint: String, buildDate: Date?, now: Date) -> Bool {
        if status == "blocked" || machineFingerprint != fingerprint { return false }
        guard let vu = Token.parse(validUntil), now <= vu else { return false }
        if let issued = Token.parse(issuedAt), now < issued.addingTimeInterval(-600) { return false } // clock set back
        if status == "lapsed" || updatesPolicy == "term" { return buildDate.map(coversBuild) ?? true }
        return status == "valid"
    }

    public func needsCheckin(now: Date) -> Bool {
        guard let after = Token.parse(checkinAfter) else { return true }
        return now >= after
    }
}

func hexBytes(_ s: String) -> Data? {
    let chars = Array(s.trimmingCharacters(in: .whitespaces))
    guard chars.count % 2 == 0 else { return nil }
    var out = Data(capacity: chars.count / 2)
    var i = 0
    while i < chars.count {
        guard let b = UInt8(String(chars[i...i + 1]), radix: 16) else { return nil }
        out.append(b)
        i += 2
    }
    return out
}

func hexString(_ d: some Sequence<UInt8>) -> String { d.map { String(format: "%02x", $0) }.joined() }

/// A public key's id: the first 16 hex characters of its SHA-256.
public func keyId(_ rawPublicKey: Data) -> String {
    String(hexString(SHA256.hash(data: rawPublicKey)).prefix(16))
}

/// Verifies licence answers against your shop's Ed25519 public keys (several during a key rotation).
public struct TokenVerifier {
    let keys: [String: Curve25519.Signing.PublicKey]

    /// - Parameter publicKeyHex: the shop's key, 64 hex characters.
    public init(publicKeyHex: String) throws {
        try self.init(publicKeysHex: [publicKeyHex])
    }

    /// - Parameter publicKeysHex: the keys to accept (the signing key first).
    public init(publicKeysHex: [String]) throws {
        var keys: [String: Curve25519.Signing.PublicKey] = [:]
        for h in publicKeysHex {
            guard let raw = hexBytes(h), raw.count == 32,
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw)
            else { throw LicenseError.config("public keys must be 64 hex characters") }
            keys[keyId(raw)] = key
        }
        self.keys = keys
    }

    /// Verify with the key named by kid (or any key) and return the payload bytes.
    public func verifyBytes(_ signed: SignedToken) throws -> Data {
        guard let raw = Data(base64Encoded: signed.payload), let sig = Data(base64Encoded: signed.signature), sig.count == 64
        else { throw LicenseError.badSignature }
        let candidates: [Curve25519.Signing.PublicKey]
        if let kid = signed.kid, !kid.isEmpty {
            candidates = keys[kid].map { [$0] } ?? []
        } else {
            candidates = Array(keys.values)
        }
        guard candidates.contains(where: { $0.isValidSignature(sig, for: raw) }) else { throw LicenseError.badSignature }
        return raw
    }

    /// Check a signed answer and parse the payload it signs.
    public func verify(_ signed: SignedToken) throws -> Token {
        let raw = try verifyBytes(signed)
        do {
            return try JSONDecoder().decode(Token.self, from: raw)
        } catch {
            throw LicenseError.badSignature
        }
    }
}
