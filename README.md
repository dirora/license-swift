# Dirora License for Swift

Licensing client for software sold through a [Dirora](https://dirora.com) shop, for Swift 5.9+ (macOS 12+, iOS 15+, Linux).

Your shop sells the licence keys. This library lets your application:

- **activate** a licence key on a machine, and **deactivate** it to free the place,
- **check in** on a schedule your shop sets, and keep working **offline** in between,
- know whether **this build** may run: after the updates period ends, a perpetual licence keeps running the versions released before the cut-off date,
- start a **free trial** on this machine, or **sign in** with the customer's account instead of typing a key,
- take a **floating seat** from a shared pool and give it back when the app closes,
- activate a machine with **no internet** through a request file and a licence file,
- count **usage** (exports, API calls, documents…) against limits your shop sets,
- **find updates** the licence covers through a **signed update manifest**, and **download** them, checked against the signed SHA-256,
- trust only answers **signed with your shop's Ed25519 keys** (with key rotation), bound to this request and this machine.

## Before you start

You need two values from your shop's admin:

| Value | Where |
|---|---|
| **Tenant** | Your shop's subdomain (`your-shop` in `your-shop.dirora.com`) or its id. |
| **Public key** | The Licences page, *public key* panel: 64 hex characters. |

Put the public key in your application's source. Never download it at run time: the key is what proves an answer came from your shop.

## Install

Swift Package Manager:

```swift
.package(url: "https://github.com/dirora/license-swift.git", from: "1.0.0")
```

Ed25519 comes from swift-crypto, which is CryptoKit on Apple platforms.

## Quick start

```swift
import DiroraLicense

var cfg = Config(tenant: "your-shop", publicKeyHex: "79b5…")   // 64 hex characters
cfg.appVersion = "2.4.0"
cfg.buildDate = ISO8601DateFormatter().date(from: "2026-11-01T00:00:00Z")
cfg.cacheURL = appSupport.appendingPathComponent("licence.json")
let client = try LicenseClient(cfg)

// Once, when the customer enters their key:
do {
    try await client.activate(key)
} catch let error as LicenseError where error.code == ErrorCode.activationLimit {
    // …
}

// Every start:
let state = await client.check()
if !state.canRun { /* show the licence screen */ }
```

Run the example with `swift run activate-example your-shop <hex> XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`.

## How a start-up check works

`check()` is the one call to make every time the application starts:

1. If the cached answer is still fresh (before its `checkin_after`), or it came from an offline licence file, it is used without going online.
2. Otherwise the library checks in. A new signed answer replaces the cache.
3. If the check-in fails because the machine is **offline**, the server is unreachable or busy (`rate_limited`), the cached answer is used, but only until its `valid_until` (the offline grace your shop allows).
4. If the server **refuses** the key (for example it was replaced, blocked or removed from this machine), there is no offline fallback.

The result says whether the application may run, whether the answer came from the server or the cache, and the error, if there was one.

### The run gate

`Token.canRun` is false when any of these is true:

- the licence is **blocked**;
- the answer is for **another machine**;
- the answer is past its **`valid_until`** (the offline grace has run out);
- the clock is **set back** more than 10 minutes before the answer was issued;
- the licence is **lapsed**, or its updates period is a fixed term, and this build was released **after `updates_until`**.

Set the **build date** to the release date of the version you ship. That date is what lets a customer whose updates period has ended keep using the versions they paid for, while newer builds refuse to run.

## Licence answer

| Field | Meaning |
|---|---|
| `status` | `valid`, `lapsed` (subscription or term ended; perpetual fallback applies) or `blocked` |
| `license_type` | The kind of licence sold |
| `updates_policy` / `updates_until` | `lifetime`, or `term` with the last date new versions are covered |
| `support_policy` / `support_until` | `lifetime`, `term` with an end date, or `none` |
| `features` | Feature flags granted by the licence; check one with `hasFeature` |
| `checkin_after` | When the application should check in again |
| `valid_until` | How long the answer may be used offline |
| `license_model` | `node_locked`, or `floating`: a seat lease that must be renewed (check in) and released |
| `auth` | `key`, or `user` when the machine is signed in with a customer account |
| `seats` | Seats on the licence (multi-seat licences) |
| `offline` | Activated with a licence file; no check-ins needed |
| `expires_at` | End of a subscription or a trial (`license_type` `trial`) |

## Updates

`checkForUpdate(channel:)` returns the shop's **signed update manifest** for this licence, platform and CPU. The library verifies its signature, that it answers this request (nonce) and this machine, before returning it:

- `update_available` and `latest`: a newer version is covered by the licence; `latest` carries `file_id` and the file's `sha256`.
- `newer_blocked`: an even newer version exists outside the updates period. Show a *renew to get it* message.

`download(_:to:)` fetches the release's file and checks it against the **signed** SHA-256 from the manifest, so a file swapped on the way is refused. Install the update only when the download succeeds.

## Activation codes and stolen keys

If your shop requires an **activation code** for new machines, the customer creates a one-time code in their account and your application passes it to activate.

If a key is **reissued** (lost or stolen), the old key stops working at once. On the next check-in the application gets `key_replaced`; ask the customer for their new key.

## Floating licences

When your shop sells a **floating** licence, activating takes a seat from the licence's pool for a short lease instead of registering the machine for good. Keep the lease alive by checking in (`check` renews it) and call `release()` when the application closes so the next person can use the seat. When every seat is taken, activation fails with `no_seat_available`; a crashed app's seat comes free when its lease runs out.

## Trials

Set `productId` in the configuration and call `startTrial(email:)`. The shop issues one trial per product and machine (a reinstall resumes the same trial instead of starting a new one). The answer's `license_type` is `trial`; `isTrial` and `trialDaysLeft(now:)` tell you what to show. Buying a licence and activating its key replaces the trial.

## Sign in with a customer account

Instead of a key, the customer can sign this machine in with their shop account (`productId` must be set):

1. `startSignIn()` returns a short **user code** and a **verification URL**. Show both, or open the URL in the browser.
2. The customer opens the page, signs in and approves the code.
3. `waitForSignIn(_:)` (or `pollSignIn(_:)` to ask once) returns the signed answer once they approve.

The machine then checks in with a private sign-in secret stored in the cache, never the key; `signedIn` tells you it is signed in. If the customer denies the request or the code expires, you get `LicenseError.signIn`.

## Offline activation

For a machine that never goes online:

1. `offlineRequest(licenseKey:)` returns request text. Save it as a `.req` file and carry it to a computer with internet.
2. The customer opens the licence in their account, uploads it under *Activate a Machine Without Internet* and gets back a **licence file**. Your shop can also create the file for them from the admin.
3. `importOfflineLicence(_:)` checks the file's signature, that it answers this machine's pending request, and stores it.

From then on the start-up check uses the file without going online, until the date your shop set for offline licences.

## Usage meters

If your shop defines **usage meters** for the product (for example `exports` per month), report usage with `reportUsage(meter:amount:idempotencyKey:)`. The answer is signed and says `used`, `limit` and `remaining` for the current period; over the limit the call fails with `usage_limit_reached`. Pass an **idempotency key** (a job id) so a retried report is counted once. An amount of `0` only reads the meter.

## Key rotation

Answers name the key that signed them (`kid`). When your shop rotates its signing key, ship a build that trusts both the old and the new public key (`extraPublicKeysHex`), then switch your shop to the new key: installed copies keep verifying answers throughout.

## Hardware info

Besides the fingerprint, the library sends **salted hashes** of a few hardware components (machine id, host name, network card, CPU, OS) and whether it runs in a **virtual machine** or container. The raw values never leave the machine. Your shop uses them to keep a machine's place after an OS reinstall, to spot a licence copied onto several machines, and, if you choose, to refuse virtual machines (`virtual_machine_not_allowed`). Turn it off with `sendHardwareInfo = false`.

## Error codes

API errors carry a stable `code`. Show your own message for each; the English `message` is for logs.

| Code | When |
|---|---|
| `invalid_request` | A required field is missing |
| `tenant_not_found` | The tenant is wrong |
| `license_not_found` | The key does not exist |
| `key_replaced` | The key was reissued; the customer has a new one |
| `license_blocked` | The licence is suspended or revoked |
| `activation_limit_reached` | All machine places are in use; deactivate one in the account |
| `activation_code_required` / `activation_code_invalid` | New machines need a valid one-time code |
| `machine_not_activated` | This machine is not activated on the key |
| `release_not_found` / `file_unavailable` | The update file cannot be served now |
| `update_not_covered` | The release is outside the updates period |
| `no_seat_available` | Every floating seat is in use; try again later |
| `virtual_machine_not_allowed` | The shop does not allow this product on virtual machines |
| `trial_not_available` / `trial_limit_reached` | The product has no trial, or this machine or network already had one |
| `sign_in_required` | The product only accepts signed-in machines |
| `device_code_invalid` | The sign-in request is unknown or was already used |
| `no_seat` | The signed-in customer has no seat assigned on the licence |
| `meter_not_found` / `usage_limit_reached` | The usage meter does not exist, or its limit is reached |
| `rate_limited` | Too many requests; the start-up check falls back to the cached answer |

A signature failure or an answer for another request is a separate error (`LicenseError.badSignature`), never an API code.

## Machine fingerprint

By default the fingerprint is the SHA-256 of the operating system's machine id (Windows `MachineGuid`, macOS `IOPlatformUUID`, Linux `/etc/machine-id`), salted with the tenant. The raw id never leaves the machine, and the value is the same in every Dirora library. **iOS has no machine id:** set `Config.fingerprint` yourself, for example a hash of `identifierForVendor`. You can pass your own stable fingerprint instead.

## Tests

```sh
swift test
```

The tests include `Tests/DiroraLicenseTests/token-v2.json`, an answer signed by the Dirora licence server, so every library is checked against the same real signature.

## Other languages

The same client for other languages: [Go](https://github.com/dirora/license-go) · [Python](https://github.com/dirora/license-python) · [Node.js](https://github.com/dirora/license-node) · [Electron](https://github.com/dirora/license-electron) · [.NET](https://github.com/dirora/license-dotnet) · [PHP](https://github.com/dirora/license-php) · [Java](https://github.com/dirora/license-java) · [Rust](https://github.com/dirora/license-rust) · [Qt](https://github.com/dirora/license-qt).

## Licence

MIT. See [LICENSE](LICENSE).
