//
// Created by Kaspek on 09.01.2023.
//

#ifndef CPPSHIELDYEXAMPLEWINAPI_SHIELDY_CPP_API_H
#define CPPSHIELDYEXAMPLEWINAPI_SHIELDY_CPP_API_H

#include <iostream>
#include <string>
#include <fstream>
#include <utility>
#include <vector>
#include <filesystem>
#include <set>
#include "windows.h"
#include "wincrypt.h"
#include <random>
#include <algorithm>
#include "comdef.h"

using random_bytes_engine = std::independent_bits_engine<
        std::random_device, CHAR_BIT, unsigned char>;

constexpr int SIGNATURE_SIZE = 256;
constexpr int MD5LEN = 32;
constexpr const char *NATIVE_LIBRARY_PATH = R"(C:\Users\Kaspek\CLionProjects\=SHIELDY=\ShieldyCore\cmake-builds\windows-x64-dev\cpp-module\native.dll)";
constexpr const char *NATIVE_LIBRARY_UPDATE_PATH = "lib/native.update";

typedef void (*MessageCallback)(int code, const char *message);
typedef void (*DownloadProgressCallback)(float progress);

enum ShieldyErrorCodes : int {
    INITIALIZE_APP_VERSION_INVALID = 1002,
    INITIALIZE_APP_DISABLED = 1004,
    INITIALIZE_APP_BANNED = 1005,
    INITIALIZE_SUCCESS = 1009,
    AUTH_LICENSE_NOT_FOUND = 1102,
    AUTH_USER_HWID_LIMIT_REACHED = 1104,
    AUTH_USER_LICENSE_EXPIRED = 1105,
    AUTH_USER_COUNTRY_BANNED = 1106,
    AUTH_EXECUTABLE_SIGNATURE_INVALID = 1111,
    AUTH_SESSION_INVALIDATED = 1113,
    AUTH_SESSION_ALREADY_USED = 1114,
    OTHER_VM_CHECK = 2000
};

#endif //CPPSHIELDYEXAMPLEWINAPI_SHIELDY_CPP_API_H

class License {
public:
    std::string mTakedHwidSeats;
    std::string mTotalHwidSeats;
    std::string mLicenseLevel;
    std::string mLicenseCreated;
    std::string mLicenseExpiry;

    License(std::string takedHwidSeats, std::string totalHwidSeats, std::string licenseLevel,
            std::string licenseCreated, std::string licenseExpiry) : mTakedHwidSeats(std::move(takedHwidSeats)),
                                                                     mTotalHwidSeats(std::move(totalHwidSeats)),
                                                                     mLicenseLevel(std::move(licenseLevel)),
                                                                     mLicenseCreated(std::move(licenseCreated)),
                                                                     mLicenseExpiry(std::move(licenseExpiry)) {}

    std::string to_string() const {
        return "License{takedHwidSeats='" + mTakedHwidSeats + "', totalHwidSeats='" + mTotalHwidSeats +
               "', licenseLevel='" + mLicenseLevel + "', licenseCreated='" + mLicenseCreated +
               "', licenseExpiry='" + mLicenseExpiry + "'}";
    }

};

class ShieldyApi {
private:
    bool late_check = false;
    std::vector<unsigned char> memoryEncryptionKey{64};
    std::string _appSalt;
    std::shared_ptr<License> _license;

    //<editor-fold desc="native bindings">
    typedef bool (init_def)(const char *licenseKey, const char *appSecret, MessageCallback messageCallback,
                            DownloadProgressCallback downloadProgressCallback);

    typedef bool (get_variable_def)(const char *secretName, char **buf, size_t *size);

    typedef bool (get_license_property_def)(const char *secret, char **buf, size_t *size);

    typedef bool (get_file_def)(const char *secret, char **fileBuf, size_t *fileSize);

    typedef bool (deobfuscate_string_def)(const char *obfB64, int rounds, char **buf, size_t *size);

    typedef bool (log_action_def)(const char *text);

    typedef bool (login_license_key_def)(const char *licenseKey);

    typedef int (get_last_error_def)();

    typedef void (free_memory_def)(void *ptr);

    get_variable_def *get_variable_ptr{};
    get_license_property_def *get_license_property_ptr{};
    get_file_def *get_file_ptr{};
    deobfuscate_string_def *deobf_str_ptr{};
    log_action_def *log_action_ptr{};
    login_license_key_def *login_license_key_ptr{};
    get_last_error_def *get_last_error_ptr{};
    free_memory_def *free_memory_ptr{};

    //</editor-fold>
    static std::string get_rsa_key();

    static bool is_file_exists(const std::string &name);

    static std::vector<unsigned char> get_native_as_bytes();

    static inline ULONG BOOL_TO_ERROR(BOOL f);

    static HRESULT
    StringToBin(_Out_ PDATA_BLOB pdb, _In_ ULONG dwFlags, _In_ PCSTR pszString, _In_ ULONG cchString = 0);

    static std::string get_last_error_string();

    static HRESULT VerifyTest(_In_ PCWSTR algorithm,
                              _In_ PCSTR keyAsPem,
                              _In_ BYTE *signatureBytes,
                              _In_ const UCHAR *dataToCheck,
                              _In_ ULONG dataToCheckSize);

    static std::vector<unsigned char> sha256_winapi(std::vector<unsigned char> data);

    static void handle_error_message(const std::string &msg);

    static std::string _xor(std::string val, const std::string &key);

    static std::string _xor(std::string val, const std::vector<unsigned char> &key);

    static std::vector<unsigned char> _xor(std::vector<unsigned char> toEncrypt, const std::string &xorKey);

    std::string get_salt();

public:
    /**
     * @brief init_def native library, should be called just after app start
     * After executing that method you can can call 'is_fully_initialized' method to check if native library is initialized
     */
    bool initialize(const std::string &appGuid, const std::string &version, const std::vector<unsigned char> &appSalt, MessageCallback messageCallback = nullptr,
                    DownloadProgressCallback downloadProgressCallback = nullptr);

    std::string get_variable(const std::string &key);

    std::string get_license_property(const std::string &key);

    std::string deobfuscate_string(const std::string &str, int rounds);

    std::vector<unsigned char> download_file(const std::string &key, bool verbose = false);

    bool log(const std::string &text);

    bool login_license_key(const std::string &licenseKey);

    bool is_fully_initialized() const;

    int get_last_error();

    License *get_license();
};

