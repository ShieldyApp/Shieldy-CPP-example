//
// Created by Kaspek on 01.03.2025.
//

#include "shieldy_api.h"









ULONG shieldy_sdk::win_utils::BOOL_TO_ERROR(WINBOOL f) {
    return f ? NOERROR : GetLastError();
}

HRESULT shieldy_sdk::win_utils::StringToBin(PDATA_BLOB pdb, ULONG dwFlags, PCSTR pszString, ULONG cchString) {
    PUCHAR pb = nullptr;
    ULONG cb = 0;

    while (CryptStringToBinaryA(pszString, cchString, dwFlags, pb, &cb, nullptr, nullptr)) {
        if (pb) {
            pdb->pbData = pb, pdb->cbData = cb;
            return S_OK;
        }

        if (!(pb = (PUCHAR) LocalAlloc(LMEM_FIXED, cb))) {
            break;
        }
    }

    return HRESULT_FROM_WIN32(GetLastError());
}

std::string shieldy_sdk::win_utils::get_last_error_string() {
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) {
        return {}; //No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &messageBuffer, 0,
            nullptr);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}

std::vector<unsigned char> shieldy_sdk::win_utils::sha256_bytes(std::vector<unsigned char> data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD cbHash = 0;
    DWORD dwCount = 0;
    BYTE rgbHash[SHA256_HASH_LEN];
    std::vector<unsigned char> result;
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
#if SHIELDY_DEBUG
        std::cout << "CryptAcquireContext failed, error " << GetLastError() << std::endl;
#endif
        return result;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
#if SHIELDY_DEBUG
        std::cout << "CryptCreateHash failed, error " << get_last_error_string() << std::endl;
#endif
        return result;
    }
    if (!CryptHashData(hHash, &data[0], data.size(), 0)) {
#if SHIELDY_DEBUG
        std::cout << "CryptHashData failed, error " << get_last_error_string() << std::endl;
#endif
        return result;
    }
    cbHash = SHA256_HASH_LEN;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
#if SHIELDY_DEBUG
        std::cout << "CryptGetHashParam failed, error " << get_last_error_string() << std::endl;
#endif
        return result;
    } else {
        for (dwCount = 0; dwCount < cbHash; dwCount++) {
            result.push_back(rgbHash[dwCount]);
        }
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

HRESULT
shieldy_sdk::win_utils::rsa_verify(PCWSTR algorithm, PCSTR keyAsPem, BYTE *signatureBytes, const UCHAR *dataToCheck,
                                   ULONG dataToCheckSize) {

    DATA_BLOB db;
    HRESULT hr;

    if (NOERROR == (hr = StringToBin(&db, CRYPT_STRING_BASE64HEADER, keyAsPem))) {
        ULONG cb;
        CERT_PUBLIC_KEY_INFO *publicKeyInfo;

        hr = BOOL_TO_ERROR(CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                               db.pbData, db.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr,
                                               &publicKeyInfo, &cb));

        LocalFree(db.pbData);

        if (NOERROR == hr) {
            BCRYPT_KEY_HANDLE hKey;

            hr = BOOL_TO_ERROR(
                    CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, publicKeyInfo, 0, nullptr, &hKey));

            LocalFree(publicKeyInfo);

            if (NOERROR == hr) {
                UCHAR hash[32];

                if (NOERROR == (hr = BOOL_TO_ERROR(
                        CryptHashCertificate2(algorithm, 0, nullptr, dataToCheck, dataToCheckSize, hash,
                                              &(cb = sizeof(hash)))))) {
                    BCRYPT_PKCS1_PADDING_INFO pi = {algorithm};

                    if (0 > (hr = BCryptVerifySignature(hKey, &pi, hash, cb, signatureBytes, SIGNATURE_SIZE,
                                                        BCRYPT_PAD_PKCS1))) {
                        hr |= FACILITY_NT_BIT;
                    }
                }

                BCryptDestroyKey(hKey);
            }
        }
    }

    return HRESULT_FROM_WIN32(hr);
}

std::string shieldy_sdk::NativeCommunication::encrypt_message(const std::string &message) {
    std::vector<unsigned char> messageVec(message.begin(), message.end());
    std::vector<unsigned char> encryptedMessage = encrypt(mEncryptionKey, messageVec.data(), messageVec.size());
    return std::string{encryptedMessage.begin(), encryptedMessage.end()};
}

std::pair<char *, size_t> shieldy_sdk::NativeCommunication::decrypt_message_safe(const char *buf, size_t len) {
    if (buf == nullptr || len < CHACHA20_NONCE_BYTES + POLY1305_MAC_BYTES) {
        return {};
    }

    std::vector<unsigned char> messageVec(buf, buf + len);
    size_t messageSize = messageVec.size() - CHACHA20_NONCE_BYTES - POLY1305_MAC_BYTES;
//    std::cout << "Decrypting message: " << dh_tests::vector_to_hex(messageVec) << std::endl;
    char *decryptedMessagePtr = new char[messageSize];
    if (!decrypt(mEncryptionKey, messageVec, decryptedMessagePtr)) {
        return {};
    }

    return {decryptedMessagePtr, messageSize};
}

#if SHIELDY_DEBUG

void shieldy_sdk::NativeCommunication::print_all() const {
    std::cout << "sdk_pub: " << utils::sha256_to_hex(mSdkPubKey, 4) << " ";
    std::cout << "sdk_priv: " << utils::sha256_to_hex(mSdkPrivKey, 4) << " ";
    std::cout << "enc_key: " << utils::sha256_to_hex(mEncryptionKey, 4) << std::endl;
}

std::string shieldy_sdk::NativeCommunication::decrypt_message(const char *buf, size_t len) {
    auto [out, outSize] = decrypt_message_safe(buf, len);
    if (out == nullptr || outSize == 0) {
        return "";
    }

    std::string result(out, outSize);
    utils::secure_zero_memory(reinterpret_cast<unsigned char *>(out), outSize);
    delete[] out;
    return result;
}

#endif

std::string shieldy_sdk::library_utils::get_public_signing_key() {
    //load public key
    //<editor-fold desc="public key">
    unsigned char s[] =
            {

                    0xb4, 0xb4, 0xb4, 0xd4, 0xac, 0xfd, 0xf5, 0x66,
                    0x95, 0x5e, 0x7d, 0xe, 0xf5, 0x7e, 0x9e, 0xf5,
                    0xe6, 0xed, 0xc5, 0x17, 0x56, 0xac, 0xcc, 0xcc,
                    0xac, 0xac, 0xc3, 0xd5, 0xd5, 0xd5, 0x8f, 0xf5,
                    0xae, 0xd5, 0xed, 0xfd, 0x41, 0xc6, 0x96, 0xce,
                    0xa6, 0x96, 0x26, 0x2c, 0xc6, 0x5, 0x8e, 0xb6,
                    0x57, 0xf6, 0x2f, 0xf6, 0x17, 0x27, 0x7, 0x37,
                    0xd7, 0x45, 0x57, 0xd7, 0xd7, 0xd7, 0x8f, 0x87,
                    0x3, 0xbd, 0xfd, 0xed, 0x8d, 0xed, 0x2e, 0x63,
                    0x6b, 0xa0, 0xce, 0xf8, 0xb5, 0xf6, 0xc5, 0xe0,
                    0xad, 0x98, 0xd3, 0xae, 0xfe, 0x51, 0xe5, 0x57,
                    0x8d, 0x5f, 0xae, 0x57, 0xdd, 0x36, 0x9e, 0x46,
                    0xdc, 0xf5, 0x78, 0x15, 0x37, 0x7f, 0xfd, 0x90,
                    0x88, 0x9f, 0xa8, 0x5f, 0xf, 0x8d, 0xf0, 0x7,
                    0x6f, 0x6f, 0xc6, 0x2e, 0x78, 0x76, 0xf, 0x7e,
                    0x96, 0x98, 0x67, 0x26, 0x87, 0x11, 0xdf, 0xf,
                    0xcd, 0xe6, 0x1f, 0xbe, 0xd5, 0xbe, 0x5f, 0xb6,
                    0x4f, 0xfd, 0x86, 0xb5, 0xdd, 0xfc, 0x7f, 0xbd,
                    0x66, 0x2e, 0x3d, 0x37, 0xef, 0xc6, 0xce, 0x1f,
                    0xe5, 0x2f, 0xa6, 0x87, 0x98, 0x58, 0x67, 0x78,
                    0x6, 0x8f, 0xc7, 0xd6, 0x74, 0x6c, 0xd6, 0x74,
                    0xf6, 0x69, 0xbe, 0x4c, 0xe7, 0x61, 0xe6, 0x4f,
                    0x9e, 0x56, 0x97, 0x7f, 0xb7, 0xe9, 0xdc, 0xd7,
                    0xbf, 0x7f, 0xf6, 0x27, 0x62, 0xae, 0xd6, 0xd6,
                    0xdd, 0xca, 0x4e, 0x2e, 0x3d, 0xae, 0x6e, 0x66,
                    0x66, 0x1b, 0x5b, 0x48, 0xbd, 0xd5, 0x9b, 0xf8,
                    0xa5, 0x6e, 0xeb, 0x37, 0x2f, 0xfe, 0x76, 0xf5,
                    0x1f, 0xd6, 0xb6, 0x17, 0xc6, 0x9f, 0x17, 0xbd,
                    0xe, 0xd, 0xd5, 0x2e, 0x3f, 0x6e, 0x8e, 0xcf,
                    0x5e, 0x96, 0xae, 0x9, 0xc8, 0xd8, 0xb7, 0xd8,
                    0x7f, 0x11, 0xa7, 0xc7, 0x7e, 0x29, 0x87, 0xe8,
                    0x46, 0x97, 0x8e, 0x9, 0x50, 0xe8, 0x7, 0x49,
                    0xa6, 0x9c, 0xd6, 0xb6, 0x4f, 0xe4, 0xe, 0x25,
                    0x94, 0x7f, 0x3e, 0xcd, 0x8e, 0x77, 0xe4, 0x17,
                    0xa6, 0x95, 0x84, 0x96, 0xce, 0xdd, 0xb6, 0x37,
                    0xb5, 0x5, 0xbe, 0x97, 0x48, 0x17, 0xd, 0x60,
                    0x4c, 0x6e, 0xb6, 0x94, 0xae, 0xde, 0xee, 0x36,
                    0xf7, 0xc, 0x3e, 0x36, 0xde, 0xde, 0x5, 0x76,
                    0x87, 0x76, 0x10, 0x77, 0xc4, 0x76, 0xbc, 0x84,
                    0xe7, 0x3f, 0xa7, 0xc6, 0xef, 0x97, 0x9a, 0x8,
                    0x78, 0xad, 0x16, 0xbd, 0xc5, 0x50, 0xdd, 0x7e,
                    0x6e, 0x5d, 0x6e, 0xbd, 0x83, 0x50, 0xde, 0xed,
                    0x17, 0xc0, 0xad, 0xe3, 0x5c, 0x68, 0x8e, 0x71,
                    0xed, 0x29, 0x96, 0x97, 0xa6, 0xd8, 0xb5, 0xbe,
                    0x8e, 0x6f, 0xb6, 0x6f, 0x78, 0xdf, 0x1f, 0xae,
                    0xf8, 0x76, 0xbf, 0xd6, 0xff, 0xdf, 0x5e, 0x9e,
                    0xee, 0x6f, 0x2f, 0x8e, 0xa6, 0xd7, 0x26, 0x36,
                    0x66, 0x97, 0x26, 0xfe, 0xde, 0xa7, 0x9f, 0x28,
                    0x75, 0x9c, 0xe6, 0x9d, 0x57, 0x17, 0x27, 0xee,
                    0xad, 0x76, 0x5f, 0x3d, 0x54, 0xbd, 0x67, 0x4c,
                    0xb6, 0xe6, 0xe7, 0x10, 0x57, 0xf, 0xff, 0xdc,
                    0x3f, 0x8d, 0x1f, 0xad, 0xc6, 0xd5, 0x5f, 0xb7,
                    0x57, 0xd5, 0xe, 0xbd, 0xb4, 0xb4, 0xb4, 0xd4,
                    0xb4, 0x76, 0x6e, 0x2e, 0x7f, 0xef, 0xf7, 0x7e,
                    0xde, 0x97, 0x7, 0x8, 0xa7, 0xf6, 0x50, 0xd4,
                    0xb4, 0xb4, 0xb4, 0xd4, 0x7d
            };

    for (unsigned int m = 0; m < sizeof(s); ++m) {
        unsigned char c = s[m];
        c = (c >> 0x3) | (c << 0x5);
        c -= 0x14;
        c = (c >> 0x1) | (c << 0x7);
        c ^= 0x59;
        c = ~c;
        c ^= 0x19;
        c = (c >> 0x7) | (c << 0x1);
        c += m;
        c = (c >> 0x2) | (c << 0x6);
        c = -c;
        c -= 0xb2;
        c = (c >> 0x6) | (c << 0x2);
        c ^= m;
        c -= 0xb;
        c ^= 0x19;
        s[m] = c;
    }
    //</editor-fold>
    std::string a(reinterpret_cast<const char *>(s));
    return a;
}

std::vector<unsigned char> shieldy_sdk::library_utils::read_native_library_bytes() {
    std::vector<unsigned char> data;

    std::ifstream libFile(NATIVE_LIBRARY_PATH, std::ios::binary);
    // Read the entire file into a vector
    data.assign(std::istreambuf_iterator<char>(libFile), std::istreambuf_iterator<char>());

    return data;
}

void shieldy_sdk::library_utils::update_if_available() {
    if (utils::is_file_exists(NATIVE_LIBRARY_UPDATE_PATH)) {
        std::filesystem::rename(NATIVE_LIBRARY_UPDATE_PATH, NATIVE_LIBRARY_PATH);
        std::filesystem::remove(NATIVE_LIBRARY_UPDATE_PATH);
    }
}

bool shieldy_sdk::library_utils::verify_native_library() {
    std::vector<unsigned char> signature;
    std::vector<unsigned char> data;
    std::vector<unsigned char> file = read_native_library_bytes();

    //get last 256 bytes (rsa signature of sha256 hash of native library)
    signature = std::vector<unsigned char>(file.end() - 256, file.end());

    //get whole file except last 256 bytes
    data = std::vector<unsigned char>(file.begin(), file.end() - 256);

    //calculate itself sha256 hash of native library
    std::vector<unsigned char> nativeSha256 = win_utils::sha256_bytes(data);

    //compare calculated md5 hash with signature which is rsa encrypted md5 hash of native library
    HRESULT hr = win_utils::rsa_verify(BCRYPT_SHA256_ALGORITHM, get_public_signing_key().c_str(),
                                       signature.data(),
                                       nativeSha256.data(),
                                       nativeSha256.size());
    if (hr != S_OK) {
        _com_error err(hr);
        LPCTSTR errMsg = err.ErrorMessage();
#if SHIELDY_DEBUG
        std::cout << "Signature verification failed, error: " << errMsg << std::endl;
#endif
        return false;
    }

    return true;
}

void shieldy_sdk::utils::generate_secure_random_bytes(unsigned char *buffer, size_t size) {
    bool success = false;

#ifdef _WIN32
    HCRYPTPROV hProvider;
    if (CryptAcquireContext(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenRandom(hProvider, size, buffer)) {
            success = true;
        }
        CryptReleaseContext(hProvider, 0);
    }
#else
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
            if (urandom) {
                urandom.read(reinterpret_cast<char*>(buffer), size);
                if (urandom.gcount() == static_cast<std::streamsize>(size)) {
                    success = true;
                }
            }
#endif

    //if failed to generate secure random bytes, use pseudo random generator
    if (!success) {
        std::random_device rd;
        for (size_t i = 0; i < size; ++i) {
            buffer[i] = rd() % 256;
        }
    }
}

void shieldy_sdk::utils::secure_zero_memory(unsigned char *data, size_t size) {
#if defined(_WIN32)
    SecureZeroMemory(data, size);
#else
    std::fill(data, data + size, 0);
#endif
}

std::vector<std::string> shieldy_sdk::utils::split_str(const std::string &str, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;

    while (std::getline(ss, item, delimiter)) {
        result.push_back(item);
    }

    return result;
}

std::string shieldy_sdk::utils::vector_to_hex(const std::vector<unsigned char> &data) {
    std::ostringstream os;
    for (unsigned char i: data) {
        os << std::hex << std::setfill('0') << std::setw(2) << (int) i;
    }
    return os.str();
}

std::string shieldy_sdk::utils::sha256_to_hex(const uint8_t *data, size_t size, int trunc) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, size);
    uint8_t hash[SHA256_BLOCK_SIZE];
    sha256_final(&ctx, hash);
    if (trunc > 0) {
        std::ostringstream os;
        for (int i = 0; i < trunc; i++) {
            os << std::hex << std::setfill('0') << std::setw(2) << (int) hash[i];
        }
        return os.str();
    } else {
        return vector_to_hex(std::vector<unsigned char>(hash, hash + SHA256_BLOCK_SIZE));
    }
}

bool shieldy_sdk::utils::is_file_exists(const std::string &name) {
    std::ifstream f(name.c_str());
    return f.good();
}

std::string shieldy_sdk::utils::sha256_to_hex(const std::vector<unsigned char> &vec, int trunc) {
    return sha256_to_hex(vec.data(), vec.size(), trunc);
}
