// Activate a licence (key, sign-in or trial) and check it, the way an app does on start-up.
//   swift run activate-example your-shop <public-key-hex> [LICENCE-KEY]
//   swift run activate-example your-shop <public-key-hex> --signin <product-id>
//   swift run activate-example your-shop <public-key-hex> --trial <product-id>
import DiroraLicense
import Foundation

let args = CommandLine.arguments
var cfg = Config(tenant: args[1], publicKeyHex: args[2])
if args.count > 4 { cfg.productId = args[4] }
cfg.appVersion = "1.0.0"
cfg.buildDate = ISO8601DateFormatter().date(from: "2026-11-01T00:00:00Z")
cfg.cacheURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".example-app/licence.json")
let client = try LicenseClient(cfg)
do {
    if args.count > 3 && args[3] == "--signin" {
        let s = try await client.startSignIn()
        print("Open \(s.verificationURL) and approve code \(s.userCode)")
        try await client.waitForSignIn(s)
    } else if args.count > 3 && args[3] == "--trial" {
        try await client.startTrial()
    } else if args.count > 3 {
        try await client.activate(args[3])
    }
} catch {
    FileHandle.standardError.write(Data("failed: \((error as? LicenseError)?.code ?? "unreachable")\n".utf8))
    exit(1)
}
let state = await client.check()
guard state.canRun, let token = state.token else {
    FileHandle.standardError.write(Data("licence not valid for this build\n".utf8))
    exit(1)
}
print("licensed (\(token.status), \(token.licenseModel ?? "node_locked"), online=\(state.online))")
if token.licenseModel == "floating" { try? await client.release() } // free the seat on exit
