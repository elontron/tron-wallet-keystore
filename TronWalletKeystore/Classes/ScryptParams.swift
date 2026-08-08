
import Foundation

/// Scrypt function parameters.
///
/// - Note (TL-KDF-001, 2026-08 audit):
///   The historical default was `n = lightN (4096), p = lightP (6)` (≈4 MiB), which
///   is the go-ethereum "light" preset. That is too weak to meaningfully slow down
///   offline brute-force of weak user passwords if the keystore ever leaves the
///   device (e.g. forensic dump, user manually exports and stores insecurely).
///   The default is now `balancedN / balancedP` (≈64 MiB, ~250–500 ms on modern
///   iPhones, ~1 s on the oldest iOS 15.1 device). We deliberately do NOT jump to
///   `standardN` (256 MiB) because that will OOM low-end supported devices.
///
/// - Note (thread & memory safety):
///   Each call site (`KeystoreKeyHeader.init(password:data:)`,
///   `KeystoreKey.decrypt(password:)`) instantiates a fresh `Scrypt` object per
///   invocation, so this struct itself is used only from one thread at a time.
///   However raising N by 16× also raises peak RAM per concurrent scrypt run
///   from ~4 MiB to ~64 MiB. If the KeyStore/TrezorCrypto call sites are ever
///   invoked concurrently (see IOS-CONC-001), two overlapping runs already cost
///   ≥128 MiB, which is close to the foreground budget on iPhone 6s. Serialize
///   the KeyStore layer alongside the IOS-CONC-001 fix.
public struct ScryptParams {
    /// Ethereum "standard" preset. Uses ≈256 MiB and ~1 s CPU on a modern desktop.
    /// Not used as the mobile default — OOMs on low-end supported devices.
    public static let standardN = 1 << 18

    /// Parallelization factor paired with `standardN`.
    public static let standardP = 1

    /// Balanced mobile default (TL-KDF-001).
    /// Peak RAM ≈ 128 * r * n = 128 * 8 * 65536 = 64 MiB.
    /// Target CPU ≈ 250–500 ms on modern iPhones, ~1 s on iPhone 6s (iOS 15.1 floor).
    public static let balancedN = 1 << 16

    /// Parallelization factor paired with `balancedN`.
    /// Matches ethereum's canonical `p = 1`, so the resulting JSON stays
    /// round-trippable with any standards-compliant wallet.
    public static let balancedP = 1

    /// Ethereum "light" preset. Uses ≈4 MiB and ~100 ms CPU on a modern desktop.
    /// Retained for backward-compat (decoding files produced with these params
    /// still works via the per-file kdfparams) and for explicit callers that need
    /// the historical value; do NOT reintroduce it as the default (see TL-KDF-001).
    public static let lightN = 1 << 12

    /// Parallelization factor paired with `lightN`.
    public static let lightP = 6

    /// Default `R` parameter of Scrypt encryption algorithm.
    public static let defaultR = 8

    /// Default desired key length of Scrypt encryption algorithm.
    public static let defaultDesiredKeyLength = 32

    /// Random salt.
    public var salt: Data

    /// Desired key length in bytes.
    public var desiredKeyLength = defaultDesiredKeyLength

    /// CPU/Memory cost factor. Defaults to `balancedN` (TL-KDF-001).
    public var n = balancedN

    /// Parallelization factor (1..232-1 * hLen/MFlen). Defaults to `balancedP`.
    public var p = balancedP

    /// Block size factor.
    public var r = defaultR

    /// Initializes with default scrypt parameters and a random salt.
    public init() {
        let length = 32
        var data = Data(repeating: 0, count: length)
        let result = data.withUnsafeMutableBytes { p in
            SecRandomCopyBytes(kSecRandomDefault, length, p)
        }
        precondition(result == errSecSuccess, "Failed to generate random number")
        salt = data
    }

    /// Initializes `ScryptParams` with all values.
    public init(salt: Data, n: Int, r: Int, p: Int, desiredKeyLength: Int) throws {
        self.salt = salt
        self.n = n
        self.r = r
        self.p = p
        self.desiredKeyLength = desiredKeyLength
        if let error = validate() {
            throw error
        }
    }

    /// Validates the parameters.
    ///
    /// - Returns: a `ValidationError` or `nil` if the parameters are valid.
    public func validate() -> ValidationError? {
        if desiredKeyLength > ((1 << 32 as Int64) - 1 as Int64) * 32 {
            return ValidationError.desiredKeyLengthTooLarge
        }
        if UInt64(r) * UInt64(p) >= (1 << 30) {
            return ValidationError.blockSizeTooLarge
        }
        if n & (n - 1) != 0 || n < 2 {
            return ValidationError.invalidCostFactor
        }
        if (r > Int.max / 128 / p) || (n > Int.max / 128 / r) {
            return ValidationError.overflow
        }
        return nil
    }

    public enum ValidationError: Error {
        case desiredKeyLengthTooLarge
        case blockSizeTooLarge
        case invalidCostFactor
        case overflow
    }
}

extension ScryptParams: Codable {
    enum CodingKeys: String, CodingKey {
        case salt
        case desiredKeyLength = "dklen"
        case n
        case p
        case r
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        salt = try values.decodeHexString(forKey: .salt)
        desiredKeyLength = try values.decode(Int.self, forKey: .desiredKeyLength)
        n = try values.decode(Int.self, forKey: .n)
        p = try values.decode(Int.self, forKey: .p)
        r = try values.decode(Int.self, forKey: .r)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(salt.hexString, forKey: .salt)
        try container.encode(desiredKeyLength, forKey: .desiredKeyLength)
        try container.encode(n, forKey: .n)
        try container.encode(p, forKey: .p)
        try container.encode(r, forKey: .r)
    }
}

