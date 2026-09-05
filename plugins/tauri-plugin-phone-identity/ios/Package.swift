// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "tauri-plugin-phone-identity",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .library(
            name: "tauri-plugin-phone-identity",
            type: .static,
            targets: ["tauri-plugin-phone-identity"]
        )
    ],
    dependencies: [.package(name: "Tauri", path: "../.tauri/tauri-api")],
    targets: [
        .target(
            name: "tauri-plugin-phone-identity",
            dependencies: [.byName(name: "Tauri"), .byName(name: "PhoneIdentityCore")],
            path: "Sources"
        ),
        .target(
            name: "PhoneIdentityCore",
            path: "Core/Sources/PhoneIdentityCore"
        ),
        .testTarget(
            name: "PhoneIdentityTests",
            dependencies: [.byName(name: "PhoneIdentityCore")],
            path: "Core/Tests/PhoneIdentityCoreTests"
        )
    ]
)
