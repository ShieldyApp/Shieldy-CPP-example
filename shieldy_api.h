//
// Created by Kaspek on 01.03.2025.
//

#ifndef CPPSHIELDYEXAMPLEWINAPI_SHIELDY_API_H
#define CPPSHIELDYEXAMPLEWINAPI_SHIELDY_API_H

#include <cstddef>
#include <random>
#include <memory>

#include "libraries/sha256.h"
#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "libraries/ChaCha20-Poly1305.hpp" // Biblioteka ChaCha20-Poly1305
#include "libraries/ecdh_utils.h"

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
    constexpr int GET_ENC_SIZE(int size) {
        return size + CHACHA20_NONCE_BYTES + POLY1305_MAC_BYTES;
    }

    constexpr int SIGNATURE_SIZE = 256;
    constexpr int SHA256_HASH_LEN = 32;
    constexpr int SHIELDY_SDK_SALT_SIZE = 32;
    constexpr int SHIELDY_SDK_CHALLENGE_NONCE_SIZE = 16;
    constexpr int SHIELDY_SDK_CHALLENGE_SIZE = GET_ENC_SIZE(SHA256_BLOCK_SIZE);

    namespace utils {

        void generate_secure_random_bytes(unsigned char *buffer, size_t size);

        void secure_zero_memory(unsigned char *data, size_t size);

        std::vector<std::string> split_str(const std::string &str, char delimiter);

        std::string vector_to_hex(const std::vector<unsigned char> &data);

        std::string sha256_to_hex(const uint8_t *data, size_t size, int trunc);

        std::string sha256_to_hex(const std::vector<unsigned char> &vec, int trunc);

        bool is_file_exists(const std::string &name);
    }

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

    namespace library_utils {
        constexpr const char *NATIVE_LIBRARY_PATH = R"(C:\Users\Kaspek\CLionProjects\=SHIELDY=\ShieldyCore\cmake-builds\windows-x64-dev\cpp-module\native.dll)";
        constexpr const char *NATIVE_LIBRARY_UPDATE_PATH = "lib/native.update";

        std::string get_public_signing_key();

        std::vector<unsigned char> read_native_library_bytes();

        void update_if_available();

        bool verify_native_library();

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

    class NativeCommunication {
    private:
        std::vector<unsigned char> mSdkPrivKey;
        std::vector<unsigned char> mSdkPubKey;
        std::vector<unsigned char> mEncryptionKey;
        std::vector<unsigned char> mAppSalt;

        static bool secure_compare_bytes(const char *a, const char *b, size_t len) {
            if (len == 0) return false;
            if (a == nullptr || b == nullptr) return false;

            //std::vector<unsigned char> aVec(len);
//            std::vector<unsigned char> bVec(len);
//            std::copy(a, a + len, aVec.begin());
//            std::copy(b, b + len, bVec.begin());
//            std::cout << "a: " << shieldy_sdk::vector_to_hex(aVec) << std::endl;
//            std::cout << "b: " << shieldy_sdk::vector_to_hex(bVec) << std::endl;

            size_t diff = 0;
            for (size_t i = 0; i < len; ++i) {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }

        static void clear_vector(std::vector<unsigned char> &vec) {
            if (!vec.empty()) {
                std::fill(vec.begin(), vec.end(), 0);
                vec.clear();
            }
        }

        static int
        extract_x_only(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
            (void) y32;
            (void) data;

            // Zakładamy, że output ma co najmniej 32 bajty
            memcpy(output, x32, 32);
            return 1;
        }

        bool gen_key_pair() {
            std::vector<unsigned char> seckey(32);
            std::vector<unsigned char> pubkey(65);
            secp256k1_pubkey pubkey_obj;

            secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
            if (fill_random(seckey.data(), seckey.size()) != 1) {
                std::cerr << "Failed to generate randomness\n";
                secp256k1_context_destroy(ctx);
                return false;
            }
            if (secp256k1_context_randomize(ctx, seckey.data()) != 1) {
                std::cerr << "Failed to randomize context\n";
                secp256k1_context_destroy(ctx);
                return false;
            }
            if (secp256k1_ec_seckey_verify(ctx, seckey.data()) != 1) {
                std::cerr << "Generated secret key is invalid\n";
                secp256k1_context_destroy(ctx);
                return false;
            }
            if (secp256k1_ec_pubkey_create(ctx, &pubkey_obj, seckey.data()) != 1) {
                std::cerr << "Failed to create public key\n";
                secp256k1_context_destroy(ctx);
                return false;
            }

            size_t len = pubkey.size();
            if (secp256k1_ec_pubkey_serialize(ctx, pubkey.data(), &len, &pubkey_obj, SECP256K1_EC_UNCOMPRESSED) != 1 ||
                len != 65) {
                std::cerr << "Failed to serialize public key\n";
                secp256k1_context_destroy(ctx);
                return false;
            }

            secp256k1_context_destroy(ctx);

            // Save secret key securely
            this->mSdkPrivKey = seckey;
            this->mSdkPubKey = pubkey;

            return true;
        }

    public:
        std::vector<unsigned char> mEncSdkPubKey{};

        NativeCommunication() = default;

        ~NativeCommunication() {
            clear_vector(mSdkPrivKey);
            clear_vector(mEncryptionKey);
            clear_vector(mAppSalt);
            clear_vector(mEncSdkPubKey);
        }


        bool initialize(const std::vector<unsigned char> &appSalt) {
            if (!gen_key_pair()) {
#if SHIELDY_DEBUG
                display_error("NativeCommunication::initialize_new: Failed to generate key pair");
#endif
                return false;
            }

            //encrypt the public key using the app salt
            mEncSdkPubKey = encrypt(appSalt, mSdkPubKey.data(), mSdkPubKey.size());
            if (mEncSdkPubKey.empty()) {
#if SHIELDY_DEBUG
                display_error("NativeCommunication::initialize: Failed to encrypt DH keys");
#endif
                return false;
            }

            //store the app salt
            this->mAppSalt = appSalt;

            return true;
        }

        bool compute_shared_secret(const std::vector<unsigned char> &nativePubKey) {
            if (mSdkPrivKey.empty()) {
#if SHIELDY_DEBUG
                display_error("NativeCommunication::compute_shared_secret: SDK private key is empty");
#endif
                return false;
            }

            secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

            if (!secp256k1_ec_seckey_verify(ctx, mSdkPrivKey.data())) {
#if SHIELDY_DEBUG
                display_error("NativeCommunication::compute_shared_secret: Invalid SDK private key");
#endif
                secp256k1_context_destroy(ctx);
                return false;
            }

            secp256k1_pubkey sdkPubKeyStruct;
            if (!secp256k1_ec_pubkey_parse(ctx, &sdkPubKeyStruct, nativePubKey.data(), nativePubKey.size())) {
#if SHIELDY_DEBUG
                display_error("NativeCommunication::compute_shared_secret: Failed to parse SDK public key");
#endif
                secp256k1_context_destroy(ctx);
                return false;
            }

            std::vector<unsigned char> sharedSecret(32);
            if (!secp256k1_ecdh(ctx, sharedSecret.data(), &sdkPubKeyStruct, mSdkPrivKey.data(), extract_x_only,
                                nullptr)) {
#if SHIELDY_DEBUG
                display_error("NativeCommunication::compute_shared_secret: ECDH failed");
#endif
                secp256k1_context_destroy(ctx);
                return false;
            }

            secp256k1_context_destroy(ctx);

            mEncryptionKey.resize(SHA256_BLOCK_SIZE);

            SHA256_CTX shaCtx;
            sha256_init(&shaCtx);
            sha256_update(&shaCtx, sharedSecret.data(), sharedSecret.size());
            sha256_update(&shaCtx, mAppSalt.data(), shieldy_sdk::SHIELDY_SDK_SALT_SIZE);
            sha256_final(&shaCtx, mEncryptionKey.data());

            // Wipe private key
            clear_vector(mSdkPrivKey);

            return true;
        }

        bool solve_challenge(const char *nonce, const char *challengeResponsEnc) {
            if (nonce == nullptr || challengeResponsEnc == nullptr) {
#if SHIELDY_DEBUG
                display_error("NativeCommunication::solve_challenge: nonce or challengeResponsEnc is null");
#endif
                return false;
            }
            std::string challengeResponse = decrypt_message(challengeResponsEnc, SHIELDY_SDK_CHALLENGE_SIZE);
            if (challengeResponse.empty()) {
#if SHIELDY_DEBUG
                display_error("NativeCommunication::solve_challenge: Failed to decrypt challenge response");
#endif
                return false;
            }

            SHA256_CTX sha256;
            sha256_init(&sha256);
            sha256_update(&sha256, reinterpret_cast<const SHA256_BYTE *>(nonce), SHIELDY_SDK_CHALLENGE_NONCE_SIZE);
            sha256_update(&sha256, mAppSalt.data(), SHIELDY_SDK_SALT_SIZE);
            sha256_update(&sha256, mEncryptionKey.data(), SHA256_BLOCK_SIZE);
            //result
            std::vector<unsigned char> shaResult(SHA256_BLOCK_SIZE);
            sha256_final(&sha256, reinterpret_cast<SHA256_BYTE *>(shaResult.data()));

            //compare with challenge response
            return secure_compare_bytes(reinterpret_cast<const char *>(shaResult.data()), challengeResponse.data(),
                                        SHA256_BLOCK_SIZE);
        }

        std::string encrypt_message(const std::string &message);

        //WARNING: this function returns a pointer to a buffer that have to be freed with delete[]
        std::pair<char *, size_t> decrypt_message_safe(const char *buf, size_t len);

        std::string decrypt_message(const char *buf, size_t len);


        static std::string get_challenge_nonce() {
            std::vector<unsigned char> nonce(SHIELDY_SDK_CHALLENGE_NONCE_SIZE);
            utils::generate_secure_random_bytes(nonce.data(), SHIELDY_SDK_CHALLENGE_NONCE_SIZE);
            return std::string{nonce.begin(), nonce.end()};
        }

        static std::vector<unsigned char>
        encrypt(const std::vector<unsigned char> &key, uint8_t *data, size_t data_size) {
            std::vector<unsigned char> nonce(CHACHA20_NONCE_BYTES); //CHACHA20_NONCE_BYTES = 12
            shieldy_sdk::utils::generate_secure_random_bytes(nonce.data(), CHACHA20_NONCE_BYTES);

            //in ChaCha20_Poly1305, cipherText is the same size as data
            std::vector<unsigned char> cipherText(data_size);
            std::vector<unsigned char> authTag(POLY1305_MAC_BYTES); //POLY1305_MAC_BYTES = 16

            ChaCha20_Poly1305::aead_encrypt(cipherText.data(), authTag.data(), data, data_size, nullptr, 0, key.data(),
                                            nonce.data());

//            std::cout << "Key: " << shieldy_sdk::vector_to_hex(std::vector<unsigned char>(key, key + 32)) << std::endl;
//            std::cout << "Nonce: " << shieldy_sdk::vector_to_hex(nonce) << std::endl;
//            std::cout << "AuthTag: " << shieldy_sdk::vector_to_hex(authTag) << std::endl;
//            std::cout << "CipherText: " << shieldy_sdk::vector_to_hex(cipherText) << std::endl;

            //CHACHA20_NONCE_BYTES + POLY1305_MAC_BYTES + data_size
            std::vector<unsigned char> outVec;
            outVec.insert(outVec.end(), nonce.begin(), nonce.end());
            outVec.insert(outVec.end(), authTag.begin(), authTag.end());
            outVec.insert(outVec.end(), cipherText.begin(), cipherText.end());
//            std::cout << "Encrypted data: " << shieldy_sdk::vector_to_hex(outVec) << std::endl;

            return outVec;
        }

        static bool decrypt(const std::vector<unsigned char> &key, std::vector<unsigned char> &data, char *out) {
            std::vector<unsigned char> nonce(CHACHA20_NONCE_BYTES); //CHACHA20_NONCE_BYTES = 12
            std::vector<unsigned char> authTag(POLY1305_MAC_BYTES); //POLY1305_MAC_BYTES = 16
            std::vector<unsigned char> cipherText(data.size() - CHACHA20_NONCE_BYTES - POLY1305_MAC_BYTES);

            //CHACHA20_NONCE_BYTES + POLY1305_MAC_BYTES + data_size
            std::copy(data.begin(), data.begin() + CHACHA20_NONCE_BYTES, nonce.begin());
            std::copy(data.begin() + CHACHA20_NONCE_BYTES, data.begin() + CHACHA20_NONCE_BYTES + POLY1305_MAC_BYTES,
                      authTag.begin());
            std::copy(data.begin() + CHACHA20_NONCE_BYTES + POLY1305_MAC_BYTES, data.end(), cipherText.begin());

            std::vector<unsigned char> decryptedAuthTag(POLY1305_MAC_BYTES); //POLY1305_MAC_BYTES = 16
            ChaCha20_Poly1305::aead_decrypt(reinterpret_cast<unsigned char *>(out), decryptedAuthTag.data(),
                                            cipherText.data(),
                                            cipherText.size(), nullptr, 0, key.data(), nonce.data());

            if (*out == 0) {
#if SHIELDY_DEBUG
                std::cout << "Decryption failed" << std::endl;
#endif
                return false;
            }

            //compare decrypted auth tag with original auth tag
            //TODO: use secure compare
            for (int i = 0; i < POLY1305_MAC_BYTES; i++) {
                if (decryptedAuthTag[i] != authTag[i]) {
#if SHIELDY_DEBUG
                    std::cout << "Decryption failed, tags do not match" << std::endl;
#endif
                    utils::secure_zero_memory(reinterpret_cast<unsigned char *>(out), data.size());
                    return false;
                }
            }

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
                                         char **nativePubKey, const char *sdkPubKey);

        typedef bool (SC_LoginLicenseKey_def)(const char *licenseKey);

        typedef char *(SC_Open_Blackbox_def)(char *challengeRequest);

        typedef bool (SC_GetVariable_def)(const char *secretName, char **buf, size_t *size);

        typedef bool (SC_GetLicenseProperty_def)(const char *secret, char **buf, size_t *size);

        typedef bool (SC_DownloadFile_def)(const char *secret, char **fileBuf, size_t *fileSize);

        typedef bool (SC_DeobfString_def)(const char *obfB64, int rounds, char **buf, size_t *size);

        typedef bool (log_action_def)(const char *text);

        typedef int (get_last_error_def)();

        typedef bool (SC_FreeMemory_def)(void *ptr);

        SC_Initialize_def *SC_Initialize_ptr{};
        SC_GetVariable_def *SC_GetVariable_ptr{};
        SC_GetLicenseProperty_def *SC_GetLicenseProperty_ptr{};
        SC_DownloadFile_def *SC_DownloadFile_ptr{};
        SC_DeobfString_def *SC_DeobfString_ptr{};
//        log_action_def *log_action_ptr{};
        SC_LoginLicenseKey_def *SC_LoginLicenseKey_ptr{};
        SC_Open_Blackbox_def *SC_Open_Blackbox_ptr{};
//        get_last_error_def *get_last_error_ptr{};
        SC_FreeMemory_def *SC_FreeMemory_ptr{};
//</editor-fold>

        bool mInitialized = false;
        bool mAuthenticated = false;
        MessageCallback mMessageCallback{};
        DownloadProgressCallback mDownloadProgressCallback{};
        std::unique_ptr<NativeCommunication> mNativeCommunication;


        bool load_library_and_bindings() {
            HINSTANCE libInstance = LoadLibrary(library_utils::NATIVE_LIBRARY_PATH);
            if (!libInstance) {
#if SHIELDY_DEBUG
                std::cout << "Failed to load native library, error: " << win_utils::get_last_error_string()
                          << std::endl;
#endif
                return false;
            }

            //<editor-fold desc="bind native exports">
            SC_Initialize_ptr = reinterpret_cast<bool (*)(const char *, const char *, int, char **,
                                                          const char *) >(GetProcAddress(libInstance,
                                                                                         "SC_Initialize"));
            SC_GetVariable_ptr = reinterpret_cast<bool (*)(const char *, char **, size_t *) > (GetProcAddress(
                    libInstance, "SC_GetVariable"));
            SC_GetLicenseProperty_ptr = reinterpret_cast<bool (*)(const char *, char **, size_t *) > (GetProcAddress(
                    libInstance, "SC_GetLicenseProperty"));
            SC_DownloadFile_ptr = reinterpret_cast<bool (*)(const char *, char **, size_t *) > (GetProcAddress(
                    libInstance, "SC_DownloadFile"));
            SC_DeobfString_ptr = reinterpret_cast<bool (*)(const char *, int, char **, size_t *) > (GetProcAddress(
                    libInstance, "SC_DeobfString"));
//            log_action_ptr = reinterpret_cast<bool (*)(const char *)>(GetProcAddress(hGetProcIDDLL,
//                                                                                     "SC_Log"));
            SC_LoginLicenseKey_ptr = reinterpret_cast<bool (*)(const char *) > (GetProcAddress(
                    libInstance, "SC_LoginLicenseKey"));
            SC_Open_Blackbox_ptr = reinterpret_cast<char *(*)(char *) > (GetProcAddress(libInstance,
                                                                                        "SC_Open_Blackbox"));
//            get_last_error_ptr = reinterpret_cast<int (*)()>(GetProcAddress(hGetProcIDDLL,
//                                                                            "SC_GetLastError"));
            SC_FreeMemory_ptr = reinterpret_cast<bool (*)(void *)>(GetProcAddress(libInstance,
                                                                                  "SC_FreeMemory"));
            //</editor-fold>

            if (!SC_Initialize_ptr || !SC_GetVariable_ptr || !SC_GetLicenseProperty_ptr || !SC_DownloadFile_ptr ||
                !SC_DeobfString_ptr ||
                !SC_LoginLicenseKey_ptr || !SC_Open_Blackbox_ptr || !SC_FreeMemory_ptr) {
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
                          << ", \nopen_blackbox_ptr: "
                          << (SC_Open_Blackbox_ptr == nullptr ? "[!] nullptr" : "not nullptr")
                          //                          << ", \nget_last_error_ptr: " << (get_last_error_ptr == nullptr ? "[!] nullptr" : "not nullptr")
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

            std::string result = mNativeCommunication->decrypt_message(buf, size);
            if (!SC_FreeMemory_ptr(&buf)) {
#if SHIELDY_DEBUG
                std::cout << "Failed to free memory for license property: " << propertyName << std::endl;
#endif
                return "";
            }
            if (result.empty()) {
#if SHIELDY_DEBUG
                std::cout << "Failed to decrypt license property: " << propertyName << std::endl;
#endif
                return "";
            }

            return result;
        }

        void load_licence_details() {
            mLicense->mTotalHwidSeats = get_license_property("hwid_total_seats");
            mLicense->mTakedHwidSeats = get_license_property("hwid_taken_seats");
            mLicense->mLicenseLevel = get_license_property("license_level");
            mLicense->mLicenseCreated = get_license_property("license_created");
            mLicense->mLicenseExpiry = get_license_property("license_expiry");
        }


        ShieldyApi() {
            mLicense = std::make_unique<License>();
            mNativeCommunication = std::make_unique<NativeCommunication>();
        }

        ~ShieldyApi() = default;

    public:
        std::unique_ptr<License> mLicense;

        //don't allow copying
        ShieldyApi(ShieldyApi const &) = delete;

        void operator=(ShieldyApi const &) = delete;

        static ShieldyApi &instance() {
            static ShieldyApi instance;
            return instance;
        }


        //core functions
        bool attest(bool skip_check = false) {
            if (!skip_check && !mInitialized) {
#if SHIELDY_DEBUG
                display_error("ShieldyCore API is not initialized while trying to perform challenge");
#endif
                return false;
            }

            std::string challengeNonce = mNativeCommunication->get_challenge_nonce();
            char *challengeResponse = SC_Open_Blackbox_ptr(challengeNonce.data());
            if (challengeResponse == nullptr) {
#if SHIELDY_DEBUG
                display_error("Failed to open blackbox, challenge response is null");
#endif
                return false;
            }

            bool result = mNativeCommunication->solve_challenge(challengeNonce.data(), challengeResponse);

            //challenge response is manually allocated by native library, so we need to free it
            if (!SC_FreeMemory_ptr(&challengeResponse)) {
#if SHIELDY_DEBUG
                display_error("Failed to free memory for challenge response");
#endif
                return false;
            }

            if (!result) {
#if SHIELDY_DEBUG
                display_error("Failed to solve challenge (perform_challenge) challenge response is incorrect");
#endif
            }

            return result;
        }

        bool
        initialize(const std::string &appGuid, const std::string &version, const std::vector<unsigned char> &appSalt) {
            try {
                if (!mNativeCommunication->initialize(appSalt)) {
                    return false;
                }

                //replace native library file if update is available
                library_utils::update_if_available();

                //check if native library is signed and not tampered
/*                if (!library_utils::verify_native_library()) {
#if SHIELDY_DEBUG
                    display_error("Native library verification failed");
#endif
                    return false;
                }*/

                //load dll and bind functions
                if (!load_library_and_bindings()) {
                    return false;
                }

//                uint8_t *nativePubKey = nullptr;
                char *nativePubKey = nullptr;
                char *sdkPubKey = reinterpret_cast<char *>(mNativeCommunication->mEncSdkPubKey.data());
                if (!SC_Initialize_ptr(appGuid.c_str(), version.c_str(), 1, &nativePubKey, sdkPubKey)) {
#if SHIELDY_DEBUG
                    display_error("Failed to initialize ShieldyCore SDK, challenge response is null");
#endif
                    return false;
                }

                std::vector<unsigned char> nativePubKeyVec(reinterpret_cast<unsigned char *>(nativePubKey),
                                                           reinterpret_cast<unsigned char *>(nativePubKey) + 65);

                //exchange public keys
                if (!mNativeCommunication->compute_shared_secret(nativePubKeyVec)) {
#if SHIELDY_DEBUG
                    display_error("Failed to compute shared secret");
#endif
                    return false;
                }

                //perform challenge to make sure that library is initialized correctly
                if (!attest(true)) {
#if SHIELDY_DEBUG
                    display_error("Failed to perform challenge during initialization");
#endif
                    return false;

                }

                //mark as initialized
                mInitialized = true;
                mNativeCommunication->print_all();

                return true;
            } catch (std::exception &e) {
#if SHIELDY_DEBUG
                display_error("Failed to initialize ShieldyCore SDK, exception appeard: " + std::string(e.what()));
#endif
                return false;
            }
        }

        bool authorize(const std::string &licenseKey) {
            try {
                if (!mInitialized) {
#if SHIELDY_DEBUG
                    display_error("ShieldyCore API is not initialized while trying to authorize");
#endif
                }

                if (!SC_LoginLicenseKey_ptr(licenseKey.c_str())) {
#if SHIELDY_DEBUG
                    display_error("Failed to login via license key");
#endif
                    return false;
                }

                //perform challenge to make sure that library is initialized correctly
                if (!attest()) {
#if SHIELDY_DEBUG
                    display_error("Failed to perform challenge during authorization");
#endif
                    return false;
                }

                load_licence_details();

                mAuthenticated = true;

                return mAuthenticated;
            } catch (std::exception &e) {
#if SHIELDY_DEBUG
                display_error("Failed to authorize, exception appeard: " + std::string(e.what()));
#endif
                return false;
            }
        }


        //misc
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


        //implementation of exported function
        std::string get_variable(const std::string &name) {
            const std::pair<char *, size_t> &variableSafe = get_variable_safe(name);
            if (variableSafe.first == nullptr || variableSafe.second == 0) {
                return "";
            }
            std::string result(variableSafe.first, variableSafe.second);

            delete[] variableSafe.first; // Free the allocated memory

            return result;
        }

        //WARNING: this function returns a pointer to a buffer that must be freed with delete[]
        std::pair<char *, size_t> get_variable_safe(const std::string &name) {
            if (!mInitialized || !mAuthenticated) {
#if SHIELDY_DEBUG
                display_error("ShieldyCore API is not initialized or not authenticated while trying to get variable");
#endif
                return {};
            }

            char *buf = nullptr;
            size_t size;

            if (!SC_GetVariable_ptr(name.c_str(), &buf, &size)) {
#if SHIELDY_DEBUG
                display_error("Failed to get variable: " + name);
#endif
                return {};
            }

            auto [decOut, decSize] = mNativeCommunication->decrypt_message_safe(buf, size);
            if (!SC_FreeMemory_ptr(&buf)) {
#if SHIELDY_DEBUG
                display_error("Failed to free memory for variable: " + name);
#endif
                return {};
            }
            if (decOut == nullptr || decSize == 0) {
#if SHIELDY_DEBUG
                display_error("Failed to decrypt variable: " + name);
#endif
                return {};
            }

            return {decOut, decSize};
        }

        std::string download_file(const std::string &secret) {
            const std::pair<char *, size_t> &fileSafe = download_file_safe(secret);
            if (fileSafe.first == nullptr || fileSafe.second == 0) {
                return "";
            }
            std::string result(fileSafe.first, fileSafe.second);

            delete[] fileSafe.first; // Free the allocated memory

            return result;
        }

        //WARNING: this function returns a pointer to a buffer that must be freed with delete[]
        std::pair<char *, size_t> download_file_safe(const std::string &name) {
            if (!mInitialized || !mAuthenticated) {
#if SHIELDY_DEBUG
                display_error("ShieldyCore API is not initialized or not authenticated while trying to download file");
#endif
                return {};

            }

            char *buf = nullptr;
            size_t size;
            if (!SC_DownloadFile_ptr(name.c_str(), &buf, &size)) {
#if SHIELDY_DEBUG
                display_error("Failed to download file: " + name);
#endif
                return {};
            }

            const std::pair<char *, size_t> &pair = mNativeCommunication->decrypt_message_safe(buf, size);

            if (!SC_FreeMemory_ptr(&buf)) {
#if SHIELDY_DEBUG
                display_error("Failed to free memory for downloaded file: " + name);
#endif
                return {};
            }

            if (pair.first == nullptr || pair.second == 0) {
#if SHIELDY_DEBUG
                display_error("Failed to decrypt downloaded file: " + name);
#endif
                return {};
            }

            return pair;
        }
    };
}

#endif //CPPSHIELDYEXAMPLEWINAPI_SHIELDY_API_H
