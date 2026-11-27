import Crypto
@testable import DiroraLicense
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest

let theKey = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"

func iso(_ d: Date) -> String { ISO8601DateFormatter().string(from: d) }

/// Answers requests like the licence API.
final class FakeAPI: URLProtocol {
    static var key = Curve25519.Signing.PrivateKey()
    static var offline = false
    static var floating = false
    static var approved = false
    static var seats = Set<String>()
    static var seen = Set<String>()
    static var used = 0
    static var deviceFp = ""

    static func reset() {
        key = Curve25519.Signing.PrivateKey()
        offline = false; floating = false; approved = false
        seats = []; seen = []; used = 0; deviceFp = ""
    }

    static var pubHex: String { hexString(key.publicKey.rawRepresentation) }

    static func sign(_ p: [String: Any]) -> [String: Any] {
        let raw = try! JSONSerialization.data(withJSONObject: p)
        let sig = try! key.signature(for: raw)
        return ["alg": "Ed25519", "kid": keyId(key.publicKey.rawRepresentation), "payload": raw.base64EncodedString(), "signature": sig.base64EncodedString()]
    }

    static func token(_ fp: Any, _ nonce: Any, auth: String, extra: [String: Any] = [:]) -> [String: Any] {
        let now = Date()
        let valid: TimeInterval = floating ? 600 : 48 * 3600
        var p: [String: Any] = ["v": 2, "status": "valid", "machine_fingerprint": fp, "nonce": nonce, "updates_policy": "lifetime",
                                "license_model": floating ? "floating" : "node_locked", "auth": auth,
                                "issued_at": iso(now), "checkin_after": iso(now + valid / 2), "valid_until": iso(now + valid)]
        p.merge(extra) { _, b in b }
        return sign(p)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    private func bodyData() -> Data {
        if let b = request.httpBody { return b }
        guard let s = request.httpBodyStream else { return Data() }
        s.open()
        defer { s.close() }
        var d = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        while s.hasBytesAvailable {
            let n = s.read(&buf, maxLength: buf.count)
            if n <= 0 { break }
            d.append(buf, count: n)
        }
        return d
    }

    private func reply(_ status: Int, _ body: Data) {
        let r = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: [:])!
        client?.urlProtocol(self, didReceive: r, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    private func data(_ d: Any) { reply(200, try! JSONSerialization.data(withJSONObject: ["data": d])) }
    private func refuse(_ status: Int, _ code: String) { reply(status, try! JSONSerialization.data(withJSONObject: ["error": code])) }

    override func startLoading() {
        if Self.offline {
            client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet))
            return
        }
        let b = (try? JSONSerialization.jsonObject(with: bodyData())) as? [String: Any] ?? [:]
        let fp = b["machine_fingerprint"] as? String ?? ""
        let nonce = b["nonce"] ?? ""
        let ok = b["license_key"] as? String == theKey || b["activation_secret"] as? String == "secret-1"
        switch request.url!.path {
        case "/activate", "/validate":
            guard ok else { return refuse(404, "license_not_found") }
            if Self.floating {
                if !Self.seats.contains(fp) && !Self.seats.isEmpty { return refuse(409, "no_seat_available") }
                Self.seats.insert(fp)
            }
            data(Self.token(fp, nonce, auth: b["activation_secret"] != nil ? "user" : "key"))
        case "/deactivate":
            Self.seats.remove(fp)
            data([String: Any]())
        case "/trials/start":
            data(["license_key": "TTTTT-TTTTT-TTTTT-TTTTT-TTTTT",
                  "token": Self.token(fp, nonce, auth: "key", extra: ["license_type": "trial", "expires_at": iso(Date() + 14 * 86400)])])
        case "/device/start":
            Self.deviceFp = fp
            data(["device_code": "dev-1", "user_code": "ABCD-EFGH", "verification_url": "https://shop/account/device", "expires_in": 900, "interval": 0])
        case "/device/poll":
            if !Self.approved { return data(["status": "pending"]) }
            data(["status": "approved", "activation_secret": "secret-1", "token": Self.token(Self.deviceFp, nonce, auth: "user")])
        case "/usage":
            var amount = b["amount"] as? Int ?? 0
            let k = b["idempotency_key"] as? String ?? ""
            if !k.isEmpty && Self.seen.contains(k) { amount = 0 }
            if Self.used + amount > 3 { return refuse(409, "usage_limit_reached") }
            Self.used += amount
            if !k.isEmpty { Self.seen.insert(k) }
            data(Self.sign(["kind": "usage", "meter": b["meter"] ?? "", "used": Self.used, "limit": 3, "remaining": 3 - Self.used,
                            "machine_fingerprint": fp, "nonce": nonce]))
        case "/updates/check":
            data(["manifest": Self.sign(["kind": "update", "machine_fingerprint": fp, "nonce": nonce, "update_available": true,
                                         "latest": ["version": "2.0.0", "file_id": "f-1", "sha256": hexString(SHA256.hash(data: Data("binary".utf8)))]])])
        case "/releases/download":
            reply(200, Data("binary".utf8))
        default:
            reply(404, Data("{}".utf8))
        }
    }
}

final class LicenseTests: XCTestCase {
    var dir: URL!
    var session: URLSession!

    override func setUp() {
        FakeAPI.reset()
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let sc = URLSessionConfiguration.ephemeral
        sc.protocolClasses = [FakeAPI.self]
        session = URLSession(configuration: sc)
    }

    func make(_ fp: String, _ file: String = "licence.json", skew: TimeInterval = 0, pub: String? = nil, extra: [String] = []) throws -> LicenseClient {
        var cfg = Config(tenant: "shop", publicKeyHex: pub ?? FakeAPI.pubHex)
        cfg.extraPublicKeysHex = extra
        cfg.productId = "p-1"
        cfg.baseURL = "https://licence.test"
        cfg.fingerprint = fp
        cfg.cacheURL = dir.appendingPathComponent(file)
        cfg.session = session
        cfg.now = { Date().addingTimeInterval(skew) }
        return try LicenseClient(cfg)
    }

    func code(_ f: () async throws -> Void) async -> String? {
        do { try await f(); return nil } catch { return (error as? LicenseError)?.code ?? "\(error)" }
    }

    func testServerVectorKidAndManifest() throws {
        let url = Bundle.module.url(forResource: "token-v2", withExtension: "json")!
        let v = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        let pubHex = v["public_key_hex"] as! String
        XCTAssertEqual(keyId(hexBytes(pubHex)!), v["kid"] as? String)
        let data = (v["response"] as! [String: Any])["data"] as! [String: Any]
        let signed = SignedToken(alg: data["alg"] as! String, payload: data["payload"] as! String, signature: data["signature"] as! String, kid: data["kid"] as? String)
        let verifier = try TokenVerifier(publicKeyHex: pubHex)
        let tok = try verifier.verify(signed)
        XCTAssertEqual(tok.status, "valid")
        XCTAssertEqual(tok.licenseModel, "node_locked")
        let d = { (s: String) in ISO8601DateFormatter().date(from: s)! }
        let fp = tok.machineFingerprint
        let now = d("2026-11-30T00:00:00Z")
        XCTAssertTrue(tok.canRun(fingerprint: fp, buildDate: d("2027-01-01T00:00:00Z"), now: now))
        XCTAssertFalse(tok.canRun(fingerprint: fp, buildDate: d("2027-08-01T00:00:00Z"), now: now))
        let raw = String(decoding: Data(base64Encoded: signed.payload)!, as: UTF8.self).replacingOccurrences(of: "\"valid\"", with: "\"VALID\"")
        let bad = SignedToken(alg: signed.alg, payload: Data(raw.utf8).base64EncodedString(), signature: signed.signature, kid: signed.kid)
        XCTAssertThrowsError(try verifier.verify(bad)) { XCTAssertEqual($0 as? LicenseError, .badSignature) }
        let m = v["update_manifest"] as! [String: Any]
        let ms = SignedToken(alg: m["alg"] as! String, payload: m["payload"] as! String, signature: m["signature"] as! String, kid: m["kid"] as? String)
        let doc = try JSONSerialization.jsonObject(with: verifier.verifyBytes(ms)) as! [String: Any]
        XCTAssertEqual((doc["latest"] as! [String: Any])["sha256"] as? String, hexString(SHA256.hash(data: Data("binary".utf8))))
    }

    func testActivateCheckOffline() async throws {
        let c = try make("fp-1")
        let notFound = await code { try await c.activate("zzzzz-zzzzz-zzzzz-zzzzz-zzzzz") }
        XCTAssertEqual(notFound, ErrorCode.licenseNotFound)
        try await c.activate(theKey.lowercased())
        let first = await c.check()
        XCTAssertTrue(first.canRun)
        FakeAPI.offline = true
        let later = await (try make("fp-1", skew: 30 * 3600)).check()
        XCTAssertTrue(later.canRun)
        XCTAssertFalse(later.online)
        let expired = await (try make("fp-1", skew: 72 * 3600)).check()
        XCTAssertFalse(expired.canRun)
    }

    func testKeyRotation() async throws {
        let old = hexString(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        try await make("fp", "a.json", pub: old, extra: [FakeAPI.pubHex]).activate(theKey)
        let onlyOld = try make("fp", "b.json", pub: old)
        do {
            try await onlyOld.activate(theKey)
            XCTFail("unknown key accepted")
        } catch {
            XCTAssertEqual(error as? LicenseError, .badSignature)
        }
    }

    func testFloatingSeatAndRelease() async throws {
        FakeAPI.floating = true
        let a = try make("fp-a", "a.json")
        let b = try make("fp-b", "b.json")
        let tok = try await a.activate(theKey)
        XCTAssertEqual(tok.licenseModel, "floating")
        let busy = await code { try await b.activate(theKey) }
        XCTAssertEqual(busy, ErrorCode.noSeatAvailable)
        try await a.release()
        XCTAssertFalse(a.licenseKey.isEmpty)
        try await b.activate(theKey)
    }

    func testTrialAndSignIn() async throws {
        let c = try make("fp-1")
        let trial = try await c.startTrial(email: "me@example.com")
        XCTAssertTrue(trial.isTrial)
        XCTAssertGreaterThanOrEqual(trial.trialDaysLeft(now: Date()), 13)
        let s = try await c.startSignIn()
        XCTAssertEqual(s.userCode, "ABCD-EFGH")
        let pending = try await c.pollSignIn(s)
        XCTAssertNil(pending)
        FakeAPI.approved = true
        let tok = try await c.waitForSignIn(s)
        XCTAssertEqual(tok.auth, "user")
        XCTAssertTrue(c.signedIn)
        let st = await c.check()
        XCTAssertTrue(st.canRun)
        XCTAssertTrue(try make("fp-1").signedIn)
    }

    func testUsageUpdatesDownload() async throws {
        let c = try make("fp-1")
        try await c.activate(theKey)
        let u1 = try await c.reportUsage(meter: "exports", amount: 2, idempotencyKey: "job-1")
        let u2 = try await c.reportUsage(meter: "exports", amount: 2, idempotencyKey: "job-1")
        XCTAssertEqual(u1.used, 2)
        XCTAssertEqual(u2.used, 2)
        let limit = await code { _ = try await c.reportUsage(meter: "exports", amount: 2, idempotencyKey: "job-2") }
        XCTAssertEqual(limit, ErrorCode.usageLimit)
        let info = try await c.checkForUpdate()
        XCTAssertTrue(info.updateAvailable)
        var rel = info.latest!
        let bin = dir.appendingPathComponent("app.bin")
        try await c.download(rel, to: bin)
        XCTAssertEqual(try String(contentsOf: bin, encoding: .utf8), "binary")
        rel.sha256 = String(repeating: "0", count: 64)
        do {
            try await c.download(rel, to: dir.appendingPathComponent("bad.bin"))
            XCTFail("tampered download accepted")
        } catch {
            XCTAssertEqual(error as? LicenseError, .checksumMismatch)
        }
    }

    func testOfflineRequestAndImport() async throws {
        let c = try make("fp-air")
        let req = try JSONSerialization.jsonObject(with: Data(base64Encoded: c.offlineRequest(licenseKey: theKey))!) as! [String: Any]
        XCTAssertEqual(req["kind"] as? String, "offline_request")
        let now = Date()
        func answer(_ nonce: Any) -> String {
            let f: [String: Any] = ["kind": "dirora_offline_licence", "v": 1, "token": FakeAPI.sign([
                "v": 2, "status": "valid", "machine_fingerprint": "fp-air", "nonce": nonce, "offline": true, "updates_policy": "lifetime",
                "issued_at": iso(now), "checkin_after": iso(now + 365 * 86400), "valid_until": iso(now + 365 * 86400)])]
            return String(decoding: try! JSONSerialization.data(withJSONObject: f), as: UTF8.self)
        }
        XCTAssertThrowsError(try c.importOfflineLicence(answer("other"))) { XCTAssertEqual($0 as? LicenseError, .badSignature) }
        XCTAssertTrue(try c.importOfflineLicence(answer(req["nonce"]!)).offline)
        FakeAPI.offline = true
        let st = await (try make("fp-air")).check()
        XCTAssertTrue(st.canRun)
        XCTAssertNil(st.error)
    }

    func testHardwareIsHashed() {
        let hw = Machine.collect(salt: "shop")
        XCTAssertTrue(hw.components.values.allSatisfy { $0.count == 64 })
        XCTAssertTrue(Machine.looksVirtual("VMware Virtual Platform"))
        XCTAssertFalse(Machine.looksVirtual("ThinkPad X1"))
    }
}
