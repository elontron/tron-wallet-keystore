import XCTest
import TronKeystore

class Tests: XCTestCase {
    /// BIP39 test vector.
    private let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private let password = "keystore-password"

    private var keyDirectory: URL!
    private var shouldRemoveKeyDirectory = true

    override func setUp() {
        super.setUp()
        keyDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        shouldRemoveKeyDirectory = true
    }

    override func tearDown() {
        if shouldRemoveKeyDirectory {
            try? FileManager.default.removeItem(at: keyDirectory)
        }
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

    func testKeyStoreDoesNotCachePlaintextHDSecrets() throws {
        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = try store.import(mnemonic: mnemonic, passphrase: "p@ss", encryptPassword: password)
        let cachedKey = try XCTUnwrap(store.key(for: account.address))

        XCTAssertNil(cachedKey.mnemonic)
        XCTAssertTrue(cachedKey.passphrase.isEmpty)
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

    /// `import(json:)` used to send every decrypted payload through the raw-key path. For an HD
    /// keystore that made the private key the first 32 characters of the mnemonic.
    func testHDKeystoreJSONRoundTripPreservesAddress() throws {
        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = try store.import(mnemonic: mnemonic, passphrase: "p@ss", encryptPassword: password)
        let json = try store.export(account: account, password: password, newPassword: password)

        let target = try KeyStore(keyDirectory: keyDirectory.appendingPathComponent("imported"))
        let imported = try target.import(json: json, password: password, newPassword: password)

        XCTAssertEqual(imported.address, account.address)
        XCTAssertEqual(imported.type, .hierarchicalDeterministicWallet)
        XCTAssertEqual(try target.exportMnemonic(account: imported, password: password), mnemonic)
        XCTAssertEqual(try target.exportPrivateKey(account: imported, password: password),
                       try store.exportPrivateKey(account: account, password: password))
    }

    /// A keystore whose declared address disagrees with the decrypted secret is tampered with.
    func testImportRejectsAddressMismatch() throws {
        let store = try KeyStore(keyDirectory: keyDirectory)
        let account = try store.import(mnemonic: mnemonic, encryptPassword: password)
        let json = try store.export(account: account, password: password, newPassword: password)

        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: json, options: []) as? [String: Any])
        object["address"] = String(repeating: "1", count: 42)
        let tampered = try JSONSerialization.data(withJSONObject: object, options: [])

        let target = try KeyStore(keyDirectory: keyDirectory.appendingPathComponent("tampered"))
        XCTAssertThrowsError(try target.import(json: tampered, password: password, newPassword: password)) { error in
            switch error as? KeyStore.Error {
            case .invalidKey: break
            default: XCTFail("expected invalidKey, got \(error)")
            }
        }
    }

    /// Mnemonic bytes must never be accepted as a raw secp256k1 scalar, at any length.
    func testKeystoreKeyRejectsMnemonicASCIIPayload() throws {
        let payload = try XCTUnwrap(mnemonic.data(using: .ascii))
        assertRejectsPrivateKey(payload)
        assertRejectsPrivateKey(payload.prefix(32))
    }

    /// 32 bytes of printable ASCII form a valid scalar, so only the guard rejects them.
    func testKeystoreKeyRejectsAllPrintableASCIIInput() {
        assertRejectsPrivateKey(Data(repeating: 0x41, count: 32))
    }

    /// The guard must not reject legitimate keys.
    func testKeystoreKeyAcceptsValid32BytePrivateKey() throws {
        let privateKey = try Wallet(mnemonic: mnemonic).getKey(at: 0).privateKey
        XCTAssertEqual(privateKey.count, 32)
        XCTAssertEqual(try KeystoreKey(password: password, key: privateKey).type, .encryptedKey)
    }

    func testConcurrentImportStoresOneAccount() throws {
        let password = self.password
        let key = try KeystoreKey(password: password, mnemonic: mnemonic)
        let json = try JSONEncoder().encode(key)
        let store = try KeyStore(keyDirectory: keyDirectory)
        let queue = DispatchQueue(label: "org.tronlink.keystore.concurrent-import", attributes: .concurrent)
        let start = DispatchSemaphore(value: 0)
        let ready = DispatchGroup()
        let group = DispatchGroup()
        let resultLock = NSLock()
        var successCount = 0
        var duplicateCount = 0
        var unexpectedErrors = [Swift.Error]()

        for _ in 0..<2 {
            ready.enter()
            group.enter()
            queue.async {
                ready.leave()
                start.wait()
                defer { group.leave() }
                do {
                    _ = try store.import(json: json, password: password, newPassword: password)
                    resultLock.lock()
                    successCount += 1
                    resultLock.unlock()
                } catch KeyStore.Error.accountAlreadyExists {
                    resultLock.lock()
                    duplicateCount += 1
                    resultLock.unlock()
                } catch {
                    resultLock.lock()
                    unexpectedErrors.append(error)
                    resultLock.unlock()
                }
            }
        }

        guard ready.wait(timeout: .now() + 5) == .success else {
            start.signal()
            start.signal()
            if group.wait(timeout: .now() + 60) != .success {
                shouldRemoveKeyDirectory = false
            }
            XCTFail("concurrent import workers failed to start")
            return
        }
        start.signal()
        start.signal()
        guard group.wait(timeout: .now() + 60) == .success else {
            // ponytail: synchronous import cannot be cancelled; use a subprocess if timeout cleanup becomes necessary.
            shouldRemoveKeyDirectory = false
            XCTFail("concurrent imports timed out")
            return
        }

        XCTAssertEqual(successCount, 1)
        XCTAssertEqual(duplicateCount, 1)
        XCTAssertTrue(unexpectedErrors.isEmpty, "unexpected errors: \(unexpectedErrors)")
        XCTAssertEqual(store.accounts.count, 1)
        let account = try XCTUnwrap(store.accounts.first)
        XCTAssertNotNil(store.key(for: account.address))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(at: keyDirectory, includingPropertiesForKeys: []).count, 1)
        XCTAssertEqual(try KeyStore(keyDirectory: keyDirectory).accounts.count, 1)
    }

    private func assertRejectsPrivateKey(_ key: Data, file: StaticString = #file, line: UInt = #line) {
        XCTAssertThrowsError(try KeystoreKey(password: password, key: key), file: file, line: line) { error in
            switch error as? EncryptError {
            case .invalidPrivateKey: break
            default: XCTFail("expected invalidPrivateKey, got \(error)", file: file, line: line)
            }
        }
    }
}
