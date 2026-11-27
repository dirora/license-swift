import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct Config {
    public var tenant: String
    public var publicKeyHex: String
    /// Further keys to accept (ship old and new during a key rotation).
    public var extraPublicKeysHex: [String] = []
    /// Product id: trials and sign-in need it.
    public var productId = ""
    public var baseURL = LicenseClient.defaultBaseURL
    /// Default: `Machine.fingerprint(salt: tenant)`. Required on iOS.
    public var fingerprint = ""
    public var machineLabel = ProcessInfo.processInfo.hostName
    public var appVersion = ""
    public var buildDate: Date?
    public var cacheURL: URL?
    /// Send hashed hardware components and the VM flag (default true).
    public var sendHardwareInfo = true
    public var session: URLSession = .shared
    public var now: () -> Date = Date.init

    public init(tenant: String, publicKeyHex: String) {
        self.tenant = tenant
        self.publicKeyHex = publicKeyHex
    }
}

/// What `LicenseClient.check()` found. `online` is false when the answer came from the cache.
public struct LicenseState {
    public let token: Token?
    public let canRun: Bool
    public let online: Bool
    public let error: Error?
}

/// A started device sign-in: show `userCode` and open `verificationURL`.
public struct SignIn {
    public let deviceCode: String
    public let userCode: String
    public let verificationURL: String
    public let expiresIn: Int
    public let interval: Int
    public let started: Date
}

/// One release named by the update manifest.
public struct ManifestRelease: Codable {
    public var version = ""
    public var channel: String?
    public var releasedAt: String?
    public var fileId: String?
    public var fileName: String?
    public var fileSize: Int?
    public var sha256: String?

    enum CodingKeys: String, CodingKey {
        case version, channel, releasedAt = "released_at", fileId = "file_id", fileName = "file_name", fileSize = "file_size", sha256
    }
}

/// The verified update manifest.
public struct UpdateInfo: Decodable {
    public let kind: String
    public let updateAvailable: Bool
    public let latest: ManifestRelease?
    /// A newer version outside the updates period (renew to get it).
    public let newerBlocked: ManifestRelease?
    public let machineFingerprint: String
    public let nonce: String

    enum CodingKeys: String, CodingKey {
        case kind, updateAvailable = "update_available", latest, newerBlocked = "newer_blocked"
        case machineFingerprint = "machine_fingerprint", nonce
    }
}

/// A usage meter's verified state.
public struct Usage: Decodable {
    public let kind: String
    public let meter: String
    public let used: Int
    public let limit: Int
    public let remaining: Int
    public let period: String?
    public let machineFingerprint: String
    public let nonce: String

    enum CodingKeys: String, CodingKey {
        case kind, meter, used, limit, remaining, period, machineFingerprint = "machine_fingerprint", nonce
    }
}

/// Talks to the licence API for one installation of your product.
///
///     var cfg = Config(tenant: "your-shop", publicKeyHex: "79b5…")   // Admin › Licences › For developers
///     cfg.appVersion = "2.4.0"
///     cfg.buildDate = ISO8601DateFormatter().date(from: "2026-11-01T00:00:00Z")
///     cfg.cacheURL = appSupport.appendingPathComponent("licence.json")
///     let client = try LicenseClient(cfg)
///     try await client.activate("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
///     let state = await client.check()   // on every start
public final class LicenseClient {
    public static let defaultBaseURL = "https://api.dirora.com/api/licenses/v"

    private struct CacheFile: Codable {
        var license_key: String?
        var activation_secret: String?
        var token: SignedToken?
        var pending_offline_nonce: String?
    }

    private var cfg: Config
    private let verifier: TokenVerifier
    private let base: String
    private lazy var hardware: Machine.HardwareInfo = cfg.sendHardwareInfo
        ? Machine.collect(salt: cfg.tenant) : Machine.HardwareInfo(components: [:], isVirtual: false)
    public private(set) var licenseKey = ""
    private var activationSecret = ""
    public var fingerprint: String { cfg.fingerprint }
    /// Whether this machine is signed in with a customer account.
    public var signedIn: Bool { !activationSecret.isEmpty }

    public init(_ config: Config) throws {
        guard !config.tenant.isEmpty else { throw LicenseError.config("tenant is required") }
        verifier = try TokenVerifier(publicKeysHex: [config.publicKeyHex] + config.extraPublicKeysHex)
        cfg = config
        base = config.baseURL.hasSuffix("/") ? String(config.baseURL.dropLast()) : config.baseURL
        if cfg.fingerprint.isEmpty { cfg.fingerprint = try Machine.fingerprint(salt: config.tenant) }
        let c = loadCache()
        licenseKey = c?.license_key ?? ""
        activationSecret = c?.activation_secret ?? ""
    }

    public func verify(_ signed: SignedToken) throws -> Token { try verifier.verify(signed) }

    private static func newNonce() -> String {
        hexString((0..<12).map { _ in UInt8.random(in: 0...255) })
    }

    private func post(_ path: String, _ body: [String: Any]) async throws -> (Data, HTTPURLResponse) {
        guard let url = URL(string: base + path) else { throw LicenseError.config("invalid baseURL") }
        var req = URLRequest(url: url, timeoutInterval: 30)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp): (Data, URLResponse) = try await withCheckedThrowingContinuation { cont in
            cfg.session.dataTask(with: req) { d, r, e in
                if let e { cont.resume(throwing: LicenseError.transport(e.localizedDescription)) }
                else if let d, let r { cont.resume(returning: (d, r)) }
                else { cont.resume(throwing: LicenseError.transport("empty response")) }
            }.resume()
        }
        guard let http = resp as? HTTPURLResponse else { throw LicenseError.transport("not HTTP") }
        if http.statusCode >= 400 {
            let e = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            throw LicenseError.api(status: http.statusCode, code: e?["error"] as? String ?? "", message: e?["message"] as? String ?? "")
        }
        return (data, http)
    }

    private func postData(_ path: String, _ body: [String: Any]) async throws -> [String: Any] {
        let (data, _) = try await post(path, body)
        guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], let d = obj["data"] as? [String: Any] else {
            throw LicenseError.transport("licence API answer is not JSON")
        }
        return d
    }

    private func clientInfo(_ body: [String: Any], nonce: String?) -> [String: Any] {
        var b = body
        b["tenant"] = cfg.tenant
        b["machine_fingerprint"] = cfg.fingerprint
        b["machine_label"] = cfg.machineLabel
        b["platform"] = Machine.platform
        b["app_version"] = cfg.appVersion
        b["components"] = hardware.components
        b["virtual"] = hardware.isVirtual
        if let nonce { b["nonce"] = nonce }
        return b
    }

    private func credential(_ body: [String: Any]) throws -> [String: Any] {
        var b = body
        if !activationSecret.isEmpty { b["activation_secret"] = activationSecret }
        else if !licenseKey.isEmpty { b["license_key"] = licenseKey }
        else { throw LicenseError.api(status: 0, code: ErrorCode.machineNotActivated, message: "no licence activated on this machine") }
        b["tenant"] = cfg.tenant
        b["machine_fingerprint"] = cfg.fingerprint
        return b
    }

    private static func signed(_ obj: Any?) throws -> SignedToken {
        guard let obj, JSONSerialization.isValidJSONObject(obj),
              let s = try? JSONDecoder().decode(SignedToken.self, from: JSONSerialization.data(withJSONObject: obj))
        else { throw LicenseError.badSignature }
        return s
    }

    private func accept(_ obj: Any?, nonce: String, store: CacheFile) throws -> Token {
        let s = try Self.signed(obj)
        let tok = try verifier.verify(s)
        guard tok.nonce == nonce, tok.machineFingerprint == cfg.fingerprint else { throw LicenseError.badSignature }
        var st = store
        st.token = s
        try saveCache(st)
        return tok
    }

    private func tokenCall(_ path: String, _ body: [String: Any], store: CacheFile) async throws -> Token {
        let nonce = Self.newNonce()
        return try accept(try await postData(path, clientInfo(body, nonce: nonce)), nonce: nonce, store: store)
    }

    private func verifiedDocument<T: Decodable>(_ obj: Any?, kind: String, nonce: String) throws -> T {
        let raw = try verifier.verifyBytes(try Self.signed(obj))
        guard let v = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any],
              v["kind"] as? String == kind, v["nonce"] as? String == nonce, v["machine_fingerprint"] as? String == cfg.fingerprint,
              let doc = try? JSONDecoder().decode(T.self, from: raw)
        else { throw LicenseError.badSignature }
        return doc
    }

    /// Register this machine (or take a floating seat) with a licence key and store the answer.
    @discardableResult
    public func activate(_ key: String, activationCode: String = "") async throws -> Token {
        let k = key.trimmingCharacters(in: .whitespaces).uppercased()
        let tok = try await tokenCall("/activate", ["license_key": k, "activation_code": activationCode], store: CacheFile(license_key: k))
        licenseKey = k
        activationSecret = ""
        return tok
    }

    /// Check in online (renews a floating seat).
    @discardableResult
    public func validate() async throws -> Token {
        try await tokenCall("/validate", try credential([:]),
                            store: CacheFile(license_key: licenseKey.isEmpty ? nil : licenseKey,
                                             activation_secret: activationSecret.isEmpty ? nil : activationSecret))
    }

    /// Free a floating seat when the app closes (the licence stays on the machine).
    public func release() async throws {
        if licenseKey.isEmpty && activationSecret.isEmpty { return }
        _ = try await post("/deactivate", try credential([:]))
    }

    /// Free this machine's place and forget the licence on it.
    public func deactivate() async throws {
        try await release()
        licenseKey = ""
        activationSecret = ""
        if let url = cfg.cacheURL { try? FileManager.default.removeItem(at: url) }
    }

    /// Start-up routine: cached answer while fresh, online when due, cache as fallback within the offline grace.
    public func check() async -> LicenseState {
        let now = cfg.now()
        let cached = cachedToken()
        if let c = cached, c.offline || !c.needsCheckin(now: now) {
            return LicenseState(token: c, canRun: c.canRun(fingerprint: cfg.fingerprint, buildDate: cfg.buildDate, now: now), online: false, error: nil)
        }
        do {
            let tok = try await validate()
            return LicenseState(token: tok, canRun: tok.canRun(fingerprint: cfg.fingerprint, buildDate: cfg.buildDate, now: cfg.now()), online: true, error: nil)
        } catch let LicenseError.api(status, code, message) where status > 0 && status < 500 && status != 429 {
            return LicenseState(token: nil, canRun: false, online: false, error: LicenseError.api(status: status, code: code, message: message))
        } catch {
            let canRun = cached?.canRun(fingerprint: cfg.fingerprint, buildDate: cfg.buildDate, now: now) ?? false
            return LicenseState(token: cached, canRun: canRun, online: false, error: error)
        }
    }

    /// Start (or resume) this machine's free trial of `Config.productId`.
    @discardableResult
    public func startTrial(email: String = "") async throws -> Token {
        guard !cfg.productId.isEmpty else { throw LicenseError.config("productId is required for trials") }
        let nonce = Self.newNonce()
        let d = try await postData("/trials/start", clientInfo(["product_id": cfg.productId, "email": email], nonce: nonce))
        let key = (d["license_key"] as? String ?? "").uppercased()
        let tok = try accept(d["token"], nonce: nonce, store: CacheFile(license_key: key))
        licenseKey = key
        activationSecret = ""
        return tok
    }

    /// Begin signing this machine in with a customer account: show `userCode` and open `verificationURL`.
    public func startSignIn() async throws -> SignIn {
        guard !cfg.productId.isEmpty else { throw LicenseError.config("productId is required for sign-in") }
        let d = try await postData("/device/start", clientInfo(["product_id": cfg.productId], nonce: nil))
        return SignIn(deviceCode: d["device_code"] as? String ?? "", userCode: d["user_code"] as? String ?? "",
                      verificationURL: d["verification_url"] as? String ?? "", expiresIn: d["expires_in"] as? Int ?? 0,
                      interval: d["interval"] as? Int ?? 5, started: cfg.now())
    }

    /// Ask once; nil while waiting for approval.
    public func pollSignIn(_ s: SignIn) async throws -> Token? {
        let nonce = Self.newNonce()
        let d = try await postData("/device/poll", ["tenant": cfg.tenant, "device_code": s.deviceCode, "nonce": nonce])
        switch d["status"] as? String {
        case "pending": return nil
        case "denied": throw LicenseError.signIn("denied")
        case "expired": throw LicenseError.signIn("expired")
        default: break
        }
        let secret = d["activation_secret"] as? String ?? ""
        let tok = try accept(d["token"], nonce: nonce, store: CacheFile(activation_secret: secret))
        licenseKey = ""
        activationSecret = secret
        return tok
    }

    @discardableResult
    public func waitForSignIn(_ s: SignIn) async throws -> Token {
        while true {
            if let tok = try await pollSignIn(s) { return tok }
            if cfg.now() > s.started.addingTimeInterval(TimeInterval(s.expiresIn)) { throw LicenseError.signIn("expired") }
            try await Task.sleep(nanoseconds: UInt64(max(s.interval, 2)) * 1_000_000_000)
        }
    }

    /// Request text for a machine without internet (save as a .req file).
    public func offlineRequest(licenseKey key: String) throws -> String {
        guard cfg.cacheURL != nil else { throw LicenseError.config("cacheURL is required for offline activation") }
        let nonce = Self.newNonce()
        var req = clientInfo(["v": 1, "kind": "offline_request", "license_key": key.trimmingCharacters(in: .whitespaces).uppercased(),
                              "product_id": cfg.productId], nonce: nonce)
        req.removeValue(forKey: "tenant")
        var cache = loadCache() ?? CacheFile()
        cache.pending_offline_nonce = nonce
        try saveCache(cache)
        return try JSONSerialization.data(withJSONObject: req).base64EncodedString()
    }

    /// Check and store the licence file answering this machine's request.
    @discardableResult
    public func importOfflineLicence(_ fileContent: String) throws -> Token {
        guard let f = (try? JSONSerialization.jsonObject(with: Data(fileContent.utf8))) as? [String: Any],
              f["kind"] as? String == "dirora_offline_licence"
        else { throw LicenseError.config("not a licence file") }
        guard let pending = loadCache()?.pending_offline_nonce, !pending.isEmpty else {
            throw LicenseError.config("no offline request is pending on this machine")
        }
        let s = try Self.signed(f["token"])
        let tok = try verifier.verify(s)
        guard tok.offline, tok.nonce == pending, tok.machineFingerprint == cfg.fingerprint else { throw LicenseError.badSignature }
        try saveCache(CacheFile(token: s))
        licenseKey = ""
        activationSecret = ""
        return tok
    }

    /// Count `amount` on a usage meter (0 reads it); retries with the same `idempotencyKey` count once.
    public func reportUsage(meter: String, amount: Int = 1, idempotencyKey: String = "") async throws -> Usage {
        let nonce = Self.newNonce()
        let d = try await postData("/usage", try credential(["meter": meter, "amount": amount, "idempotency_key": idempotencyKey, "nonce": nonce]))
        return try verifiedDocument(d, kind: "usage", nonce: nonce)
    }

    /// The verified update manifest (`channel`: "stable" | "beta").
    public func checkForUpdate(channel: String = "stable") async throws -> UpdateInfo {
        let nonce = Self.newNonce()
        let d = try await postData("/updates/check", try credential([
            "current_version": cfg.appVersion, "platform": Machine.platform, "arch": Machine.arch, "channel": channel, "nonce": nonce,
        ]))
        return try verifiedDocument(d["manifest"], kind: "update", nonce: nonce)
    }

    /// Download a release (from the manifest) to `destination`, written only when the signed SHA-256 matches.
    public func download(_ release: ManifestRelease, to destination: URL) async throws {
        let (data, http) = try await post("/releases/download", try credential(["file_id": release.fileId ?? ""]))
        let want = (release.sha256.flatMap { $0.isEmpty ? nil : $0 } ?? http.value(forHTTPHeaderField: "X-Checksum-SHA256") ?? "").lowercased()
        if !want.isEmpty && want != hexString(SHA256.hash(data: data)) { throw LicenseError.checksumMismatch }
        try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: destination, options: .atomic)
    }

    private func loadCache() -> CacheFile? {
        guard let url = cfg.cacheURL, let d = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(CacheFile.self, from: d)
    }

    private func saveCache(_ f: CacheFile) throws {
        guard let url = cfg.cacheURL else { return }
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(f).write(to: url, options: .atomic)
    }

    private func cachedToken() -> Token? {
        guard let s = loadCache()?.token else { return nil }
        return try? verifier.verify(s)
    }
}
