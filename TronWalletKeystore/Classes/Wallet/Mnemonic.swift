
import Foundation
import TronCore

public final class Mnemonic {
    /// Generates a menmoic string with the given strength in bits.
    ///
    /// - Precondition: `strength` is a multiple of 32 between 128 and 256
    /// - Parameter strength: strength in bits
    /// - Returns: mnemonic string
    public static func generate(strength: Int) -> String {
        precondition(strength % 32 == 0 && strength >= 128 && strength <= 256)
        let length = 240
        var buffer = [CChar](repeating: 0, count: length)
        guard let rawString = buffer.withUnsafeMutableBufferPointer({ buf in
            mnemonic_generate(Int32(strength), buf.baseAddress, Int32(length))
        }) else {
            return ""
        }
        return String(cString: rawString)
    }

    /// Generates a mnemonic from seed data.
    ///
    /// - Precondition: the length of `data` is a multiple of 4 between 16 and 32
    /// - Parameter data: seed data for the mnemonic
    /// - Returns: mnemonic string
    public static func generate(from data: Data) -> String {
        precondition(data.count % 4 == 0 && data.count >= 16 && data.count <= 32)
        let length = 240
        var buffer = [CChar](repeating: 0, count: length)
        let rawString = buffer.withUnsafeMutableBufferPointer { buf -> UnsafePointer<CChar>? in
            data.withUnsafeBytes { (dataPtr: UnsafeRawBufferPointer) -> UnsafePointer<CChar>? in
                guard let baseAddress = dataPtr.baseAddress else {
                    return nil
                }
                return mnemonic_from_data(baseAddress.assumingMemoryBound(to: UInt8.self), Int32(data.count), buf.baseAddress, Int32(length))
            }
        }
        guard let rawStringValue = rawString else {
            return ""
        }
        return String(cString: rawStringValue)
    }

    /// Determines if a mnemonic string is valid.
    ///
    /// - Parameter string: mnemonic string
    /// - Returns: `true` if the string is valid; `false` otherwise.
    public static func isValid(_ string: String) -> Bool {
        guard let asciiCString = string.cString(using: String.Encoding.ascii) else {
            return false
        }
        return mnemonic_check(asciiCString) != 0
    }

    /// Derives the wallet seed.
    ///
    /// - Parameters:
    ///   - mnemonic: mnemonic string
    ///   - passphrase: mnemonic passphrase
    /// - Returns: wallet seed
    public static func deriveSeed(mnemonic: String, passphrase: String) -> Data {
        precondition(passphrase.count <= 256, "Passphrase too long")
        var seed = Data(repeating: 0, count: 512 / 8)
        let result = seed.withUnsafeMutableBytes { seedPtr in
            mnemonic_to_seed(mnemonic, passphrase, seedPtr.bindMemory(to: UInt8.self).baseAddress, nil)
        }
        precondition(result == 1, "mnemonic_to_seed failed")
        return seed
    }
}

extension Mnemonic {
    enum Error: Swift.Error {
        case invalidStrength
    }
}
