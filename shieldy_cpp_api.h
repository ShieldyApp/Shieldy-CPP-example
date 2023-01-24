//
// Created by Kaspek on 09.01.2023.
//

#ifndef CPPSHIELDYEXAMPLEWINAPI_SHIELDY_CPP_API_H
#define CPPSHIELDYEXAMPLEWINAPI_SHIELDY_CPP_API_H

#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <filesystem>
#include <set>
#include "windows.h"
#include "wincrypt.h"
#include <random>
#include "comdef.h"

using namespace std;
using random_bytes_engine = std::independent_bits_engine<
        std::random_device, CHAR_BIT, unsigned char>;

#define SIGNATURE_SIZE 256
#define MD5LEN 16
#define NATIVE_LIBRARY_PATH "lib/native.dll"
#define NATIVE_LIBRARY_UPDATE_PATH "lib/native.update"

#endif //CPPSHIELDYEXAMPLEWINAPI_SHIELDY_CPP_API_H

class ShieldyApi {
private:
    bool late_check = false;
    vector<unsigned char> memoryEncryptionKey{64};
    string _appSalt;

    //<editor-fold desc="native bindings">
    typedef bool (init)(const char *licenseKey, const char *appSecret);

    typedef bool (get_variable_def)(const char *secretName, char **buf, size_t *size);

    typedef bool (get_user_property_def)(const char *secret, char **buf, size_t *size);

    typedef bool (get_file_def)(const char *secret, char **fileBuf, size_t *fileSize);

    typedef bool (deobfuscate_string_def)(const char *obfB64, int rounds, char **buf, size_t *size);

    typedef bool (log_action_def)(const char *text);

    typedef bool (login_license_key_def)(const char *licenseKey);

    get_variable_def *get_variable_ptr{};
    get_user_property_def *get_user_property_ptr{};
    get_file_def *get_file_ptr{};
    deobfuscate_string_def *deobf_str_ptr{};
    log_action_def *log_action_ptr{};
    login_license_key_def *login_license_key_ptr{};

    //</editor-fold>

    static string get_rsa_key();

    static bool is_file_exists(const std::string &name);

    static vector<unsigned char> get_native_as_bytes();

    static inline ULONG BOOL_TO_ERROR(BOOL f);

    static HRESULT
    StringToBin(_Out_ PDATA_BLOB pdb, _In_ ULONG dwFlags, _In_ PCSTR pszString, _In_ ULONG cchString = 0);

    static HRESULT VerifyTest(_In_ PCWSTR algorithm,
                              _In_ PCSTR keyAsPem,
                              _In_ BYTE *signatureBytes,
                              _In_ const UCHAR *dataToCheck,
                              _In_ ULONG dataToCheckSize);

    static vector<unsigned char> md5_winapi(vector<unsigned char> data);

    static void handle_error_message(const string &msg);

    static string _xor(string val, const string &key);

    static string _xor(string val, const vector<unsigned char> &key);

    static vector<unsigned char> _xor(vector<unsigned char> toEncrypt, const string &xorKey);

    string get_salt();

public:
    /**
     * @brief init native library, should be called just after app start
     * After executing that method you can can call 'is_fully_initialized' method to check if native library is initialized
     */
    void initialize(const std::string &appGuid, const std::string &version, const std::string &appSalt);

    string get_variable(const string &key);

    string get_user_property(const string &key);

    string deobfuscate_string(const string &str, int rounds);

    vector<unsigned char> download_file(const string &key, bool verbose = false);

    bool log(const string &text);

    bool login_license_key(const string &licenseKey);

    bool is_fully_initialized();
};

