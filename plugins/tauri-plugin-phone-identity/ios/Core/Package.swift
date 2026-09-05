// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PhoneIdentityCore",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [.library(name: "PhoneIdentityCore", targets: ["PhoneIdentityCore"])],
    targets: [
        .target(name: "PhoneIdentityCore"),
        .testTarget(name: "PhoneIdentityCoreTests", dependencies: ["PhoneIdentityCore"])
    ]
)
