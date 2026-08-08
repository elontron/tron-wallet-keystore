import XCTest
import TronKeystore

class Tests: XCTestCase {
    /// BIP39 test vector.
    private let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private let password = "keystore-password"

    private var keyDirectory: URL!

    override func setUp() {
        super.setUp()
        keyDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: keyDirectory)
        super.tearDown()
    }

    /// The passphrase is a BIP39 derivation input, so losing it across a restart silently
    /// re-derives a different private key for the same address.
    func testPassphraseSurvivesReload() throws {
        let passphrase = "correct horse battery staple"

        let store = try KeyStore(keyDirectory: keyDirectory)
        _ = try store.import(mnemonic: mnemonic, passphrase: passphrase, encryptPassword: password)

        let reloaded = try KeyStore(keyDirectory: keyDirectory)
        let account = try XCTUnwrap(reloaded.accounts.first)
        let exported = try reloaded.exportPrivateKey(account: account, password: password)

        let expected = try Wallet(mnemonic: mnemonic, passphrase: passphrase).getKey(at: 0).privateKey
        XCTAssertEqual(exported, expected)
    }

    /// An empty passphrase must keep producing the pre-existing payload layout, otherwise keys
    /// written by earlier versions no longer decode.
    func testKeyWithoutPassphraseSurvivesReload() throws {
        let store = try KeyStore(keyDirectory: keyDirectory)
        _ = try store.import(mnemonic: mnemonic, encryptPassword: password)

        let reloaded = try KeyStore(keyDirectory: keyDirectory)
        let account = try XCTUnwrap(reloaded.accounts.first)
        XCTAssertEqual(try reloaded.exportMnemonic(account: account, password: password), mnemonic)

        let expected = try Wallet(mnemonic: mnemonic).getKey(at: 0).privateKey
        XCTAssertEqual(try reloaded.exportPrivateKey(account: account, password: password), expected)
    }

    /// Guards the round trip against a payload split that would hand the passphrase bytes back
    /// as part of the mnemonic.
    func testExportedMnemonicExcludesPassphrase() throws {
        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = try store.import(mnemonic: mnemonic, passphrase: "p@ss", encryptPassword: password)
        XCTAssertEqual(try store.exportMnemonic(account: account, password: password), mnemonic)
    }

    func testDifferentPassphrasesDeriveDifferentKeys() throws {
        let a = try Wallet(mnemonic: mnemonic, passphrase: "one").getKey(at: 0).privateKey
        let b = try Wallet(mnemonic: mnemonic, passphrase: "two").getKey(at: 0).privateKey
        XCTAssertNotEqual(a, b)
    }

    /// The C layer bounds the passphrase in bytes. Checking `String.count` let a multi-byte
    /// passphrase past the guard and turned the derivation failure into a trap.
    func testOverlongMultiBytePassphraseThrows() {
        let passphrase = String(repeating: "🔑", count: 65) // 65 characters, 260 UTF-8 bytes
        XCTAssertEqual(passphrase.count, 65)
        XCTAssertEqual(passphrase.utf8.count, 260)
        XCTAssertThrowsError(try Mnemonic.deriveSeed(mnemonic: mnemonic, passphrase: passphrase))
    }

    /// A 256-byte passphrase is exactly at the limit and must still derive.
    func testPassphraseAtByteLimitDerives() throws {
        let passphrase = String(repeating: "a", count: 256)
        XCTAssertEqual(try Mnemonic.deriveSeed(mnemonic: mnemonic, passphrase: passphrase).count, 64)
    }

    /// `EthereumCrypto` reports an invalid private key by returning an empty `Data`, since its
    /// return type is `nonnull`. Decoding an address from that used to trap, including in release
    /// builds, rather than surfacing an error.
    func testInvalidPrivateKeyThrowsInsteadOfTrapping() {
        XCTAssertThrowsError(try KeystoreKey(password: password, key: Data(repeating: 1, count: 16)))
        XCTAssertThrowsError(try KeystoreKey(password: password, key: Data(repeating: 0, count: 32)))
    }
}
