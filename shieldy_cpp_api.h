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
#include "comdef.h"

using namespace std;

#define SIGNATURE_SIZE 256
#define MD5LEN 16
#define NATIVE_LIBRARY_PATH "lib/native.dll"
#define NATIVE_LIBRARY_UPDATE_PATH "lib/native.update"

#endif //CPPSHIELDYEXAMPLEWINAPI_SHIELDY_CPP_API_H

class ShieldyApi {
private:
    bool late_check = false;

    //<editor-fold desc="native bindings">
    typedef bool (init)(char *licenseKey, char *appSecret);

    typedef bool (get_secret_def)(char *secret, char **buf);

    typedef bool (get_user_property_def)(char *secret, char **buf);

    typedef bool (get_file_def)(char *secret, char **fileBuf, size_t *fileSize);

    typedef bool (deobfuscate_string_def)(const char *obfuscatedBase64, char **fileBuf, int rounds);

    get_secret_def *get_secret_ptr{};
    get_user_property_def *get_user_property_ptr{};
    get_file_def *get_file_ptr{};
    deobfuscate_string_def *deobf_str_ptr{};

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

public:
    /**
     * @brief init native library, should be called just after app start
     * After executing that method you can can call 'is_fully_initialized' method to check if native library is initialized
     */
    void initialize(const std::string &licenseKey, const std::string &appSecret);

    string get_secret(const string &key);

    string get_user_property(const string &key);

    string deobfuscate_string(const string &key, int rounds);

    vector<unsigned char> download_file(const string &key, bool verbose = false);

    bool is_fully_initialized();
};

