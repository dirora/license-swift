// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DiroraLicense",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "DiroraLicense", targets: ["DiroraLicense"]),
        .executable(name: "activate-example", targets: ["ActivateExample"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"4.0.0"),
    ],
    targets: [
        .target(name: "DiroraLicense", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .executableTarget(name: "ActivateExample", dependencies: ["DiroraLicense"]),
        .testTarget(
            name: "DiroraLicenseTests",
            dependencies: ["DiroraLicense", .product(name: "Crypto", package: "swift-crypto")],
            resources: [.copy("token-v2.json")]
        ),
    ]
)
