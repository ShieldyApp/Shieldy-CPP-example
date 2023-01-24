//
// Created by Kaspek on 09.01.2023.
//

#include "shieldy_cpp_api.h"

string ShieldyApi::get_rsa_key() {
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
    string a(reinterpret_cast<const char *>(s));
    return a;
}

bool ShieldyApi::is_file_exists(const string &name) {
    ifstream f(name.c_str());
    return f.good();
}

vector<unsigned char> ShieldyApi::get_native_as_bytes() {
    vector<unsigned char> data;
    string libPath = "lib/native.dll";

    ifstream libFile(libPath, ios::binary);
    // Read the entire file into a vector
    data.assign(istreambuf_iterator<char>(libFile), istreambuf_iterator<char>());

    return data;
}

ULONG ShieldyApi::BOOL_TO_ERROR(WINBOOL f) {
    return f ? NOERROR : GetLastError();
}

HRESULT ShieldyApi::StringToBin(PDATA_BLOB pdb, ULONG dwFlags, PCSTR pszString, ULONG cchString) {
    PUCHAR pb = 0;
    ULONG cb = 0;

    while (CryptStringToBinaryA(pszString, cchString, dwFlags, pb, &cb, 0, 0)) {
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

vector<unsigned char> ShieldyApi::md5_winapi(vector<unsigned char> data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD cbHash = 0;
    DWORD dwCount = 0;
    BYTE rgbHash[MD5LEN];
    vector<unsigned char> result;
    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            if (CryptHashData(hHash, &data[0], data.size(), 0)) {
                cbHash = MD5LEN;
                if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
                    for (dwCount = 0; dwCount < cbHash; dwCount++) {
                        result.push_back(rgbHash[dwCount]);
                    }
                }
            }
        }
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

void ShieldyApi::handle_error_message(const string &msg) {
    MessageBoxA(nullptr, msg.c_str(), "Error", MB_OK | MB_ICONERROR);
}

void ShieldyApi::initialize(const std::string &appGuid, const std::string &version, const std::string &appSalt) {
    try {
        _appSalt = appSalt;

        //do update if exists
        if (is_file_exists(NATIVE_LIBRARY_UPDATE_PATH)) {
            std::filesystem::rename(NATIVE_LIBRARY_UPDATE_PATH, NATIVE_LIBRARY_PATH);
            filesystem::remove(NATIVE_LIBRARY_UPDATE_PATH);
        }

        if (!is_file_exists(NATIVE_LIBRARY_PATH)) {
            cout << "Native library not found" << endl;
            exit(1);
            return;
        }

        vector<unsigned char> signature;
        vector<unsigned char> data;
        const vector<unsigned char> &file = get_native_as_bytes();

        //get last 256 bytes
        signature = vector<unsigned char>(file.end() - 256, file.end());

        //get whole file except last 256 bytes
        data = vector<unsigned char>(file.begin(), file.end() - 256);

        //do md5_winapi
        vector<unsigned char> md5_data = md5_winapi(data);

        //check signature
        HRESULT hr = VerifyTest(BCRYPT_SHA256_ALGORITHM, get_rsa_key().c_str(), signature.data(), md5_data.data(),
                                md5_data.size());

        if (hr != S_OK) {
            _com_error err(hr);
            LPCTSTR errMsg = err.ErrorMessage();
            handle_error_message("Signature verification failed, error: " + string(errMsg));
            return;
        }

        HINSTANCE hGetProcIDDLL = LoadLibrary(NATIVE_LIBRARY_PATH);
        if (!hGetProcIDDLL) {
            handle_error_message("Failed to load native library, error: " + to_string(GetLastError()));
            return;
        }

        init *sc_initialize = reinterpret_cast<bool (*)(const char *, const char *)>(GetProcAddress(hGetProcIDDLL,
                                                                                                    "SC_Initialize"));
        get_variable_ptr = reinterpret_cast<bool (*)(const char *, char **, size_t *)>(GetProcAddress(hGetProcIDDLL,
                                                                                                      "SC_GetVariable"));
        get_user_property_ptr = reinterpret_cast<bool (*)(const char *, char **, size_t *)>(GetProcAddress(
                hGetProcIDDLL,
                "SC_GetUserProperty"));
        get_file_ptr = reinterpret_cast<bool (*)(const char *, char **, size_t *)>(GetProcAddress(
                hGetProcIDDLL,
                "SC_DownloadFile"));
        deobf_str_ptr = reinterpret_cast<bool (*)(const char *, int, char **, size_t *)>(GetProcAddress(
                hGetProcIDDLL,
                "SC_DeobfString"));
        log_action_ptr = reinterpret_cast<bool (*)(const char *)>(GetProcAddress(hGetProcIDDLL,
                                                                                 "SC_Log"));
        login_license_key_ptr = reinterpret_cast<bool (*)(const char *)>(GetProcAddress(hGetProcIDDLL,
                                                                                        "SC_LoginLicenseKey"));
        cout << log_action_ptr("Initializing Shieldy API") << endl;
        if (!sc_initialize || !get_variable_ptr || !get_user_property_ptr || !get_file_ptr || !deobf_str_ptr) {
            handle_error_message("Failed to load native library, missing functions");
            return;
        }

        if (sc_initialize(strdup(appGuid.c_str()), strdup(version.c_str()))) {
            late_check = true;
        }

    } catch (exception &e) {
        handle_error_message("Failed to verify native library, error: " + string(e.what()));
    }
}

HRESULT ShieldyApi::VerifyTest(PCWSTR algorithm, PCSTR keyAsPem, BYTE *signatureBytes, const UCHAR *dataToCheck,
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

            hr = BOOL_TO_ERROR(CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, publicKeyInfo, 0, nullptr, &hKey));

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

/***
 * @return - true if user successfully logged in, false otherwise
 */
bool ShieldyApi::is_fully_initialized() {
    return late_check;
}

/***
 * Get authenticated user property from Shieldy
 * Available properties:
 * - username
 * - avatar (as base64 string)
 * - accessLevel
 * - licenseCreated (as unix timestamp)
 * - licenseExpiry (as unix timestamp)
 * - hwidLimit
 * - lastAccessDate (as unix timestamp)
 * - lastAccessIp
 * - files (as string by comma)
 * - variables (as string by comma)
 * - hwid
 *
 * @param key - avaiable property key
 * @return - property value, empty string if not found
 * @example - get_user_property("username") -> "John Doe"
 */
string ShieldyApi::get_user_property(const string &key) {
    if (!is_fully_initialized()) { // if not initialized, do not log
        cout << "Please initialize ShieldyApi before usage " << __FUNCTION__ << "()" << endl;
        return "";
    }

    string result;
    char *secret = nullptr;
    size_t size;

    if (get_user_property_ptr(strdup(key.c_str()), &secret, &size)) {
        result = string(secret, size);
        delete[] secret;
    }
    return _xor(result, _appSalt);
}

/***
 * Get variable from Shieldy
 * Variables are securely stored in Shieldy and can be accessed only by Shieldy API
 * They are encrypted with AES-256 and are decrypted on the fly
 * Without authorization, this function will return an empty string
 *
 * @see https://dashboard.shieldy.app/assets
 * @param key name of the secret
 * @return variable value, empty string if not found
 * @example get_variable("my_secret")
 */
string ShieldyApi::get_variable(const string &key) {
    if (!is_fully_initialized()) { // if not initialized, do not log
        cout << "Please initialize ShieldyApi before usage " << __FUNCTION__ << "()" << endl;
        return "";
    }

    string result;
    char *secret = nullptr;
    size_t size;
    if (get_variable_ptr(strdup(key.c_str()), &secret, &size)) {
        result = string(secret, size);
        delete[] secret;
    }

    return _xor(result, _appSalt);;
}

/**
 * Download file from Shieldy
 * File must be uploaded to Shieldy dashboard
 * Files are encrypted with AES with unique key for each app
 *
 * @see https://dashboard.shieldy.app/assets
 * @param key - name of the file, must be the same as in dashboard
 * @param verbose - if true, will print success and error messages
 * @return file content as vector of bytes, empty vector if failed
 */
vector<unsigned char> ShieldyApi::download_file(const string &key, bool verbose) {
    if (!is_fully_initialized()) { // if not initialized, do not log
        cout << "Please initialize ShieldyApi before usage " << __FUNCTION__ << "()" << endl;
        return {};
    }

    vector<unsigned char> fileBytes = {};

    if (verbose) {
        cout << "Downloading file " << key << endl;
    }
    char *fileBuf = nullptr;
    size_t fileSize;

    bool result = get_file_ptr(strdup(key.c_str()), &fileBuf, &fileSize);
    if (result) {
        if (verbose) cout << "File downloaded successfully" << endl;
        fileBytes = vector<unsigned char>(fileBuf, fileBuf + fileSize);
    } else {
        if (verbose) cout << "Failed to download file" << endl;
    }

    delete[] fileBuf;
    return _xor(fileBytes, _appSalt);
}

/***
 * Deobfuscate string
 * Best way to store sensitive data in your app
 * For example, you can obfuscate any API key in Shieldy dashboard and deobfuscate it in your app
 * Strings are encrypted with AES-256 and are decrypted on the fly using unique key for each app
 * Without authorization, this function will return an empty string
 *
 * @param str - obfuscated string in base64
 * @param rounds - number of rounds, must be the same as returned in dashboard
 * @return deobfuscated string, empty string if failed
 * @example deobfuscate_string("Zm9vYmFy", 1) -> "foobar"
 */
string ShieldyApi::deobfuscate_string(const string &str, int rounds) {
    if (!is_fully_initialized()) { // if not initialized, do not log
        cout << "Please initialize ShieldyApi before usage " << __FUNCTION__ << "()" << endl;
        return "";
    }

    string result;
    char *secret = nullptr;
    size_t size;

    if (deobf_str_ptr(strdup(str.c_str()), rounds, &secret, &size)) {
        result = string(secret, size);
        delete[] secret;
    }

    return _xor(result, _appSalt);;
}

/***
 * Log custom action to Shieldy dashboard
 *
 * All logs are visible in dashboard under "Logs" tab
 *
 * @see https://dashboard.shieldy.app/logs
 * @param text - text to log
 * @return true if logged successfully
 * @example log("User logged in");
 */
bool ShieldyApi::log(const string &text) {
    if (!is_fully_initialized()) { // if not initialized, do not log
        cout << "Please initialize ShieldyApi before usage " << __FUNCTION__ << "()" << endl;
        return false;
    }

    return log_action_ptr(strdup(text.c_str()));
}

bool ShieldyApi::login_license_key(const string &licenseKey) {
    if (!is_fully_initialized()) {
        cout << "Please initialize ShieldyApi before usage " << __FUNCTION__ << "()" << endl;
        return false;
    }

    return login_license_key_ptr(strdup(licenseKey.c_str()));
}

string ShieldyApi::_xor(string val, string key) {
    for (size_t i = 0; i < val.length(); i++) {
        val[i] = val[i] ^ key[i % key.length()];
    }
    return val;
}

vector<unsigned char> ShieldyApi::_xor(vector<unsigned char> toEncrypt, string xorKey) {
    for (size_t i = 0; i < toEncrypt.size(); i++) {
        toEncrypt[i] = toEncrypt[i] ^ xorKey[i % xorKey.size()];
    }

    return toEncrypt;
}