//
// Created by Kaspek on 01.03.2025.
//

#ifndef CPPSHIELDYEXAMPLEWINAPI_SHIELDY_API_H
#define CPPSHIELDYEXAMPLEWINAPI_SHIELDY_API_H

#include <cstddef>
#include <random>
#include <memory>

#include "libraries/sha256.h"
#include "libraries/ecdh.h" // Biblioteka tiny-ECDH-c
#include "libraries/ChaCha20-Poly1305.hpp" // Biblioteka ChaCha20-Poly1305

#ifdef _WIN32

#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <comdef.h>
#include <filesystem>

#else
#include <fstream>
#endif

#define SHIELDY_API_WRAPPER_DEBUG 1

#ifdef SHIELDY_API_WRAPPER_DEBUG
#define SHIELDY_DEBUG 1


#else
#define SHIELDY_DEBUG 0
#endif

namespace shieldy_sdk {
    constexpr int SIGNATURE_SIZE = 256;
    constexpr int SHA256_HASH_LEN = 32;
    constexpr int SHIELDY_SDK_SALT_SIZE = 32;
    constexpr int MEMORY_ENCRYPTION_KEY_SIZE = 64;
    constexpr const char *NATIVE_LIBRARY_PATH = R"(C:\Users\Kaspek\CLionProjects\=SHIELDY=\ShieldyCore\cmake-builds\windows-x64-dev\cpp-module\native.dll)";
    constexpr const char *NATIVE_LIBRARY_UPDATE_PATH = "lib/native.update";
    using random_bytes_engine = std::independent_bits_engine<
            std::random_device, CHAR_BIT, unsigned char>;

    namespace win_utils {
        ULONG BOOL_TO_ERROR(WINBOOL f);

        HRESULT StringToBin(_Out_ PDATA_BLOB pdb, _In_ ULONG dwFlags, _In_ PCSTR pszString, _In_ ULONG cchString = 0);

        std::string get_last_error_string();

        std::vector<unsigned char> sha256_bytes(std::vector<unsigned char> data);

        HRESULT rsa_verify(_In_ PCWSTR algorithm,
                           _In_ PCSTR keyAsPem,
                           _In_ BYTE *signatureBytes,
                           _In_ const UCHAR *dataToCheck,
                           _In_ ULONG dataToCheckSize);
    }

    std::string vector_to_hex(const std::vector<unsigned char> &data);

    bool is_file_exists(const std::string &name);

    std::vector<std::string> split(const std::string &str, char delimiter);

    void generate_secure_random_bytes(unsigned char *buffer, size_t size);

    void xor_bytes(unsigned char *data, size_t dataSize, unsigned const char *key, size_t keySize);

    void xor_bytes(char *data, size_t dataSize, unsigned const char *key, size_t keySize);

    void secure_zero_memory(unsigned char *data, size_t size);

    std::string get_rsa_key();


    std::vector<unsigned char> read_native_library_bytes();

    bool verify_native_library();

    void update_if_available();

    class NativeCommunication {
    private:

    public:
        uint8_t mSdkPrivKey[ECC_PRV_KEY_SIZE]{};
        uint8_t mSdkPubKey[ECC_PUB_KEY_SIZE]{};
        uint8_t mEncryptionKey[SHA256_BLOCK_SIZE]{};

        NativeCommunication() {
            generate_secure_random_bytes(mSdkPrivKey, ECC_PRV_KEY_SIZE);
            generate_secure_random_bytes(mSdkPubKey, ECC_PUB_KEY_SIZE);

            int genKey = ecdh_generate_keys(mSdkPubKey, mSdkPrivKey);
            if (genKey != 1) {
#if SHIELDY_DEBUG
                std::cout << "Failed to generate ECDH keys" << std::endl;
#endif
                exit(0);
            }
        }

        ~NativeCommunication() {
            secure_zero_memory(mSdkPrivKey, ECC_PRV_KEY_SIZE);
            secure_zero_memory(mSdkPubKey, ECC_PUB_KEY_SIZE);
            secure_zero_memory(mEncryptionKey, SHA256_BLOCK_SIZE);
        }


        bool compute_shared_secret(const uint8_t *nativePubKey, const uint8_t *appSalt);

        std::vector<unsigned char> encrypt_sdk_public_key(const uint8_t *appSalt);

        std::string encrypt_message(const std::string &message);

        std::string decrypt_message(const std::string &message);

        static std::vector<unsigned char> encrypt(const uint8_t *key, uint8_t *data, size_t data_size) {
            std::vector<unsigned char> AAD = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                              0x0}; //AAD - Additional Authenticated Data
            std::vector<unsigned char> nonce(CHACHA20_NONCE_BYTES); //CHACHA20_NONCE_BYTES = 12
            shieldy_sdk::generate_secure_random_bytes(nonce.data(), CHACHA20_NONCE_BYTES);

            std::vector<unsigned char> cipherText(
                    data_size); //in ChaCha20_Poly1305, cipherText is the same size as data
            std::vector<unsigned char> authTag(POLY1305_MAC_BYTES); //POLY1305_MAC_BYTES = 16

            ChaCha20_Poly1305::aead_encrypt(cipherText.data(), authTag.data(), data, data_size, nullptr, 0, key,
                                            nonce.data());

            //CHACHA20_NONCE_BYTES + POLY1305_MAC_BYTES + data_size
            std::vector<unsigned char> outVec;
            outVec.insert(outVec.end(), nonce.begin(), nonce.end());
            outVec.insert(outVec.end(), authTag.begin(), authTag.end());
            outVec.insert(outVec.end(), cipherText.begin(), cipherText.end());

            std::cout << "ENC Encrypted data: " << vector_to_hex(cipherText) << std::endl;
            std::cout << "ENC Auth tag: " << vector_to_hex(authTag) << std::endl;
            std::cout << "ENC Nonce: " << vector_to_hex(nonce) << std::endl;
            std::cout << "ENC Full: " << vector_to_hex(outVec) << std::endl;


            return outVec;
        }

        static bool decrypt(const uint8_t *key, std::vector<unsigned char> &data, std::vector<unsigned char> &out) {
            std::vector<unsigned char> nonce(CHACHA20_NONCE_BYTES); //CHACHA20_NONCE_BYTES = 12
            std::vector<unsigned char> authTag(POLY1305_MAC_BYTES); //POLY1305_MAC_BYTES = 16
            std::vector<unsigned char> cipherText(data.size() - CHACHA20_NONCE_BYTES - POLY1305_MAC_BYTES);

            std::copy(data.begin(), data.begin() + CHACHA20_NONCE_BYTES, nonce.begin());
            std::copy(data.begin() + CHACHA20_NONCE_BYTES, data.begin() + CHACHA20_NONCE_BYTES + POLY1305_MAC_BYTES,
                      authTag.begin());
            std::copy(data.begin() + CHACHA20_NONCE_BYTES + POLY1305_MAC_BYTES, data.end(), cipherText.begin());

            std::cout << "DEC Full: " << vector_to_hex(data) << std::endl;
            std::cout << "DEC Nonce: " << vector_to_hex(nonce) << std::endl;
            std::cout << "DEC Auth tag: " << vector_to_hex(authTag) << std::endl;
            std::cout << "DEC Cipher text: " << vector_to_hex(cipherText) << std::endl;

            std::vector<unsigned char> decryptedAuthTag(POLY1305_MAC_BYTES); //POLY1305_MAC_BYTES = 16
            std::vector<unsigned char> decryptedData(cipherText.size());

            ChaCha20_Poly1305::aead_decrypt(decryptedData.data(), decryptedAuthTag.data(), cipherText.data(),
                                            cipherText.size(), nullptr, 0, key, nonce.data());

            std::cout << "DEC Decrypted auth tag: " << vector_to_hex(decryptedAuthTag) << std::endl;
            std::cout << "DEC Decrypted data: " << vector_to_hex(decryptedData) << std::endl;

            if (decryptedAuthTag != authTag) {
                std::cout << "Auth tags do not match" << std::endl;
                std::cout << "Expected: " << std::endl;
                for (const auto &c: authTag) {
                    std::cout << std::hex << static_cast<int>(c) << " ";
                }
                std::cout << std::endl;

                std::cout << "Got: " << std::endl;
                for (const auto &c: decryptedAuthTag) {
                    std::cout << std::hex << static_cast<int>(c) << " ";
                }
                std::cout << std::endl;
                return false;
            }

            out = decryptedData;

            return true;
        }


#if SHIELDY_DEBUG

        void print_all() const;

#endif

    };

    class License {
    public:
        std::string mTakedHwidSeats;
        std::string mTotalHwidSeats;
        std::string mLicenseLevel;
        std::string mLicenseCreated;
        std::string mLicenseExpiry;

        [[nodiscard]] std::string to_string() const {
            return "License{takedHwidSeats='" + mTakedHwidSeats + "', totalHwidSeats='" + mTotalHwidSeats +
                   "', licenseLevel='" + mLicenseLevel + "', licenseCreated='" + mLicenseCreated +
                   "', licenseExpiry='" + mLicenseExpiry + "'}";
        }
    };

    class ShieldyApi {
    private:
        //<editor-fold desc="native bindings">
        typedef void (*MessageCallback)(int code, const char *message);

        typedef void (*DownloadProgressCallback)(float progress);

        typedef bool (SC_Initialize_def)(const char *appGuid, const char *appVersion, int appMode,
                                         uint8_t **nativePubKey, uint8_t *sdkPubKey);

        typedef bool (SC_LoginLicenseKey_def)(const char *licenseKey, char **buf, size_t *size);

        typedef bool (SC_GetVariable_def)(const char *secretName, char **buf, size_t *size);

        typedef bool (SC_GetLicenseProperty_def)(const char *secret, char **buf, size_t *size);

        typedef bool (SC_DownloadFile_def)(const char *secret, char **fileBuf, size_t *fileSize);

        typedef bool (SC_DeobfString_def)(const char *obfB64, int rounds, char **buf, size_t *size);

        typedef bool (log_action_def)(const char *text);

        typedef int (get_last_error_def)();

        typedef void (SC_FreeMemory_def)(void *ptr);

        SC_Initialize_def *SC_Initialize_ptr{};
        SC_GetVariable_def *SC_GetVariable_ptr{};
        SC_GetLicenseProperty_def *SC_GetLicenseProperty_ptr{};
        SC_DownloadFile_def *SC_DownloadFile_ptr{};
        SC_DeobfString_def *SC_DeobfString_ptr{};
//        log_action_def *log_action_ptr{};
        SC_LoginLicenseKey_def *SC_LoginLicenseKey_ptr{};
//        get_last_error_def *get_last_error_ptr{};
        SC_FreeMemory_def *SC_FreeMemory_ptr{};
//</editor-fold>

        bool mInitialized = false;
        bool mAuthenticated = false;
        unsigned char *mAppSalt{};
        unsigned char *mMemoryEncryptionKey{};
        MessageCallback mMessageCallback{};
        DownloadProgressCallback mDownloadProgressCallback{};

        std::unique_ptr<License> mLicense;
        std::unique_ptr<NativeCommunication> mNativeCommunication;


        bool load_library_and_bindings() {
            HINSTANCE hGetProcIDDLL = LoadLibrary(NATIVE_LIBRARY_PATH);
            if (!hGetProcIDDLL) {
#if SHIELDY_DEBUG
                std::cout << "Failed to load native library, error: " << win_utils::get_last_error_string()
                          << std::endl;
#endif
                return false;
            }

            //<editor-fold desc="bind native exports">
            SC_Initialize_ptr =
                    reinterpret_cast<bool (*)(const char *, const char *, int, unsigned char **, unsigned char *) >
                    (GetProcAddress(hGetProcIDDLL,
                                    "SC_Initialize"));
            SC_GetVariable_ptr = reinterpret_cast<bool (*)(const char *, char **, size_t *) > (GetProcAddress(
                    hGetProcIDDLL,
                    "SC_GetVariable"));
            SC_GetLicenseProperty_ptr = reinterpret_cast<bool (*)(const char *, char **, size_t *) > (GetProcAddress(
                    hGetProcIDDLL, "SC_GetLicenseProperty"));
            SC_DownloadFile_ptr = reinterpret_cast<bool (*)(const char *, char **, size_t *) > (GetProcAddress(
                    hGetProcIDDLL, "SC_DownloadFile"));
            SC_DeobfString_ptr = reinterpret_cast<bool (*)(const char *, int, char **, size_t *) > (GetProcAddress(
                    hGetProcIDDLL, "SC_DeobfString"));
//            log_action_ptr = reinterpret_cast<bool (*)(const char *)>(GetProcAddress(hGetProcIDDLL,
//                                                                                     "SC_Log"));
            SC_LoginLicenseKey_ptr = reinterpret_cast<bool (*)(const char *, char **, size_t *) > (GetProcAddress(
                    hGetProcIDDLL, "SC_LoginLicenseKey"));
//            get_last_error_ptr = reinterpret_cast<int (*)()>(GetProcAddress(hGetProcIDDLL,
//                                                                            "SC_GetLastError"));
            SC_FreeMemory_ptr = reinterpret_cast<void (*)(void *)>(GetProcAddress(hGetProcIDDLL,
                                                                                  "SC_FreeMemory"));
            //</editor-fold>

            if (!SC_Initialize_ptr || !SC_GetVariable_ptr || !SC_GetLicenseProperty_ptr || !SC_DownloadFile_ptr ||
                !SC_DeobfString_ptr ||
                !SC_LoginLicenseKey_ptr) {
#if SHIELDY_DEBUG
                std::cout << "Failed to load native library, missing functions" << std::endl;
                std::cout << "Raport: init_ptr: " << (SC_Initialize_ptr == nullptr ? "[!] nullptr" : "not nullptr") <<
                          ", \nget_variable_ptr: " << (SC_GetVariable_ptr == nullptr ? "[!] nullptr" : "not nullptr") <<
                          ", \nget_license_property_ptr: "
                          << (SC_GetLicenseProperty_ptr == nullptr ? "[!] nullptr" : "not nullptr") <<
                          ", \nget_file_ptr: " << (SC_DownloadFile_ptr == nullptr ? "[!] nullptr" : "not nullptr") <<
                          ", \ndeobf_str_ptr: " << (SC_DeobfString_ptr == nullptr ? "[!] nullptr" : "not nullptr") <<
                          //                          ", \nlog_action_ptr: " << (log_action_ptr == nullptr ? "[!] nullptr" : "not nullptr") <<
                          ", \nlogin_license_key_ptr: "
                          << (SC_LoginLicenseKey_ptr == nullptr ? "[!] nullptr" : "not nullptr")
                          //                          ", \nget_last_error_ptr: " << (get_last_error_ptr == nullptr ? "[!] nullptr" : "not nullptr")
                          << std::endl;
#endif
                return false;
            }


            return true;
        }

        std::string get_license_property(const std::string &propertyName) {
            char *buf = nullptr;
            size_t size;
            if (!SC_GetLicenseProperty_ptr(propertyName.c_str(), &buf, &size)) {
#if SHIELDY_DEBUG
                std::cout << "Failed to get license property: " << propertyName << std::endl;
#endif
                return "";
            }

            std::string result(buf, size);
            SC_FreeMemory_ptr(&buf);
            return result;

        }

        void load_licence_details() {
            mLicense->mTotalHwidSeats = get_license_property("hwid_total_seats");
            mLicense->mTakedHwidSeats = get_license_property("hwid_taken_seats");
            mLicense->mLicenseLevel = get_license_property("license_level");
            mLicense->mLicenseCreated = get_license_property("license_created");
            mLicense->mLicenseExpiry = get_license_property("license_expiry");
            std::cout << "License-> " << mLicense->to_string() << std::endl;
        }

        ShieldyApi() {
            mAppSalt = new unsigned char[SHIELDY_SDK_SALT_SIZE];
            mMemoryEncryptionKey = new unsigned char[MEMORY_ENCRYPTION_KEY_SIZE];
            mLicense = std::make_unique<License>();
            mNativeCommunication = std::make_unique<NativeCommunication>();
        }

        ~ShieldyApi() {
            delete[] mAppSalt;
            delete[] mMemoryEncryptionKey;
        }


#if SHIELDY_DEBUG

        static void display_error(const std::string &msg) {
            std::string title = "Fatal error while initializing ShieldyCore SDK";
            std::string fullMsg = "A problem appeard: \n" + msg +
                                  "\n\nIf you need assistance, please contact support at https://shieldy.app/support";
#if _WIN32
            MessageBoxA(nullptr, fullMsg.c_str(), title.c_str(),
                        MB_ICONINFORMATION | MB_SYSTEMMODAL);
#else
            std::cerr << title << ": " << fullMsg << std::endl;

#endif
        }

#endif


    public:
        //don't allow copying
        ShieldyApi(ShieldyApi const &) = delete;

        void operator=(ShieldyApi const &) = delete;

        static ShieldyApi &instance() {
            static ShieldyApi instance;
            return instance;
        }


        bool set_callbacks(MessageCallback messageCallback, DownloadProgressCallback downloadProgressCallback) {
            if (messageCallback == nullptr) {
#if SHIELDY_DEBUG
                display_error("Message callback is null");
#endif
                return false;
            }
            if (downloadProgressCallback == nullptr) {
#if SHIELDY_DEBUG
                display_error("Download progress callback is null");
#endif
                return false;
            }

            mMessageCallback = messageCallback;
            mDownloadProgressCallback = downloadProgressCallback;
            return true;
        }

        bool initialize(const std::string &appGuid, const std::string &version, const unsigned char *appSalt) {
            if (appSalt == nullptr) {
#if SHIELDY_DEBUG
                display_error("App salt is null, cannot initialize ShieldyCore API");
#endif
                return false;
            }
            memcpy_s(mAppSalt, SHIELDY_SDK_SALT_SIZE, appSalt, SHIELDY_SDK_SALT_SIZE);

            //replace native library file if update is available
            update_if_available();

            //check if native library is signed and not tampered
            if (!verify_native_library()) {
#if SHIELDY_DEBUG
                display_error("Native library verification failed");
#endif
                return false;
            }

            //load dll and bind functions
            if (!load_library_and_bindings()) {
                return false;
            }

            uint8_t *nativePubKey = nullptr;
//            auto encryptSdkPublicKey = mNativeCommunication->encrypt_sdk_public_key(appSalt);
            if (!SC_Initialize_ptr(appGuid.c_str(), version.c_str(), 1, &nativePubKey,
                                   mNativeCommunication->mSdkPubKey)) {
#if SHIELDY_DEBUG
                display_error("Failed to initialize ShieldyCore API, initialize function returned false");
#endif
                return false;
            }

            if (!mNativeCommunication->compute_shared_secret(nativePubKey, appSalt)) {
#if SHIELDY_DEBUG
                display_error("Failed to compute shared secret");
#endif
                return false;
            }

            mNativeCommunication->print_all();

            mInitialized = true;

            return true;
        }

        bool authorize(const std::string &licenseKey) {
            try {
                if (!mInitialized) {
#if SHIELDY_DEBUG
                    display_error("ShieldyCore API is not initialized while trying to authorize");
#endif
                }

                char *buf = nullptr;
                size_t size;
                time_t currentTime = time(nullptr);

                if (!SC_LoginLicenseKey_ptr(licenseKey.c_str(), &buf, &size)) {
#if SHIELDY_DEBUG
                    display_error("Failed to authorize");
#endif
                    return false;
                }

                if (size == 0 || buf == nullptr || size > 1024) {
#if SHIELDY_DEBUG
                    display_error(
                            "Failed to authorize, auth sequence is empty or too long. Size: " + std::to_string(size) +
                            ", buf: " + (buf == nullptr ? "nullptr" : "not nullptr") + ", license key: " +
                            licenseKey +
                            "\nContact support for assistance");
#endif
                    return false;
                }

/*                std::string authResultSequence(buf, size);

                //decrypt the auth sequence
                xor_bytes(authResultSequence.data(), authResultSequence.size(), mAppSalt, SHIELDY_SDK_SALT_SIZE);

                //format: seed1,hash,seed2
                std::vector<std::string> vector = split(authResultSequence, ',');

                std::string seed1 = vector.at(0);
                std::string timeHash = vector.at(1);
                std::string seed2 = vector.at(2);

                //allow 1-minute difference
                int diff = -60;
                for (int i = 0; i < 120; i++) {
                    std::string loopStr = seed1;
                    loopStr += std::to_string(currentTime + diff + i);
                    loopStr += seed2;

                    std::string hash = picosha2::hash256_hex_string(loopStr);
                    if (hash == timeHash) {
                        mAuthenticated = true;
                    }
                }*/

                if (!mAuthenticated) {
#if SHIELDY_DEBUG
                    display_error("Failed to authorize, time does not match - please check your system time");
#endif
                    return false;
                }

                load_licence_details();

                return mAuthenticated;
            } catch (std::exception &e) {
#if SHIELDY_DEBUG
                display_error("Failed to authorize, exception appeard: " + std::string(e.what()));
#endif
                return false;
            }
        }

        bool double_verify() {
            //add variable hash check
            return mAuthenticated && mInitialized;
        }
    };
}

namespace dh_tests {

    std::string vector_to_hex(const std::vector<unsigned char> &data);

    std::string sha256_to_hex(const uint8_t *data, size_t size, int trunc = 0);

    /*void initialize_secure_communication() {
        // 1. Generowanie kluczy ECDH w SDK
        uint8_t sdk_private_key[ECC_PRV_KEY_SIZE];
        uint8_t sdk_public_key[ECC_PUB_KEY_SIZE];
        int genKey = ecdh_generate_keys(sdk_public_key, sdk_private_key);
        if (genKey != 1) {
            return;
        }

        // 2. Szyfrowanie klucza publicznego SDK
        uint8_t nonce[CHACHA20_NONCE_BYTES] = {0}; // Należy użyć unikalnego nonce dla każdej operacji
        uint8_t auth_tag[POLY1305_MAC_BYTES];
        uint8_t encrypted_sdk_public_key[ECC_PUB_KEY_SIZE];

        chacha20_poly1305_encrypt(app_salt, nonce, sdk_public_key, ECC_BYTES, encrypted_sdk_public_key, auth_tag);

        // 3. Przesłanie zaszyfrowanego klucza publicznego SDK do biblioteki natywnej
        SC_Initialize(encrypted_sdk_public_key, auth_tag, nonce);

        // 4. Otrzymanie zaszyfrowanego klucza publicznego z biblioteki natywnej
        uint8_t encrypted_native_public_key[ECC_BYTES];
        uint8_t native_auth_tag[16];
        receive_encrypted_native_public_key(encrypted_native_public_key, native_auth_tag);

        // 5. Odszyfrowanie klucza publicznego biblioteki natywnej
        uint8_t native_public_key[ECC_BYTES];
        chacha20_poly1305_decrypt(app_salt, nonce, encrypted_native_public_key, ECC_BYTES, native_public_key,
                                  native_auth_tag);

        // 6. Obliczenie wspólnego sekretu
        uint8_t shared_secret[ECC_BYTES];
        ecdh_shared_secret(native_public_key, sdk_private_key, shared_secret);

        // 7. Użycie wspólnego sekretu do dalszej komunikacji
        // ...
    }*/
}


#endif //CPPSHIELDYEXAMPLEWINAPI_SHIELDY_API_H
