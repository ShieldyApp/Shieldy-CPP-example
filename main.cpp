#include <iostream>
#include <string>
#include <thread>
#include "shieldy_cpp_api.h"
#include "board.h"

//global variable which allow to access the api from anywhere
ShieldyApi shieldy;

namespace utils {
    bool save_file(const string &path, const vector<unsigned char> &data) {
        try {
            filesystem::path file_path(path);
            filesystem::create_directories(file_path.parent_path());
            ofstream file(path, ios::binary | ios::out);
            if (!file.good()) {
                cout << "Could not create file at path: " << path << endl;
                return false;
            }
            file.write(reinterpret_cast<const char *>(data.data()), static_cast<streamsize>(data.size()));
            file.close();
        } catch (exception &e) {
            cout << "Could not create directories: " << e.what() << endl;
            return false;
        }
        return true;
    }

    vector<string> split_string(const string &i_str, const string &i_delim) {
        vector<string> result;

        size_t found = i_str.find(i_delim);
        size_t startIndex = 0;

        while (found != string::npos) {
            result.push_back(string(i_str.begin() + startIndex, i_str.begin() + found));
            startIndex = found + i_delim.size();
            found = i_str.find(i_delim, startIndex);
        }
        if (startIndex != i_str.size())
            result.push_back(string(i_str.begin() + startIndex, i_str.end()));
        return result;
    }

    //you can read license key from file or using gui, its only example
    string read_license_key() {
        string licenseKeyPath = "license.txt";

        ifstream iostream(licenseKeyPath.c_str());

        //<editor-fold desc="license file not exists">
        if (!iostream.good()) {
            ofstream outfile(licenseKeyPath.c_str());
            outfile << "XXXXXX-XXXXXX-XXXXX";
            outfile.close();

            filesystem::path p = licenseKeyPath.c_str();

            cout << "License key not found.\nPlease enter valid license key in 'license.txt'\n\nFile created at:\n"
                 << filesystem::absolute(p).string() << endl;
            exit(0);
        }
        //</editor-fold>
        stringstream buffer;
        buffer << iostream.rdbuf();

        return buffer.str();
    }
}

//example User object which contains user data obtained from api
class User {

public:
    string username;
    string avatar;
    int accessLevel = 0;
    int licenseCreated = 0;
    int licenseExpiry = 0;
    int hwidLimit = 0;
    int lastAccessDate = 0;
    string lastAccessIp;
    vector<string> files = {};
    vector<string> variables = {};
    string hwid;

    explicit User(ShieldyApi api) {
        username = api.get_user_property("username");
        avatar = api.get_user_property("avatar");
        accessLevel = stoi(api.get_user_property("accessLevel"));
        licenseCreated = stoi(api.get_user_property("licenseCreated"));
        licenseExpiry = stoi(api.get_user_property("licenseExpiry"));
        hwidLimit = stoi(api.get_user_property("hwidLimit"));
        lastAccessDate = stoi(api.get_user_property("lastAccessDate"));
        lastAccessIp = api.get_user_property("lastAccessIp");
        files = utils::split_string(api.get_user_property("files"), ";");
        variables = utils::split_string(api.get_user_property("variables"), ";");
        hwid = api.get_user_property("hwid");
    }

    friend ostream &operator<<(ostream &os, const User &user) {
        os << "USER" << endl << endl;
        os << "username: " << user.username << endl;
        os << "avatar: " << user.avatar << endl;
        os << "accessLevel: " << user.accessLevel << endl;
        os << "licenseCreated: " << user.licenseCreated << endl;
        os << "licenseExpiry: " << user.licenseExpiry << endl;
        os << "hwidLimit: " << user.hwidLimit << endl;
        os << "lastAccessDate: " << user.lastAccessDate << endl;
        os << "lastAccessIp: " << user.lastAccessIp << endl;
        os << "files: " << endl;
        for (auto &file: user.files) {
            os << file << endl;
        }
        os << "variables: " << endl;
        for (auto &variable: user.variables) {
            os << variable << endl;
        }
        os << "hwid: " << user.hwid << endl;
        os << endl;
        return os;
    }
};

//src: https://github.com/zachbellay/tictactoe
int play() {

    auto secret = shieldy.get_variable("PerApp");
    cout << "Secret: " << secret << endl;
    if (secret.empty() || !shieldy.is_fully_initialized()) {
        return 1;
    }

    int board_size;
    bool x_turn = true;

    cout << "2 Player Tic Tac Toe:" << endl;
    cout << "How large should the board be? (Enter a whole number): ";
    cin >> board_size;
    tictactoe::board b(board_size);
    while (!b.x_win() && !b.o_win()) {
        cout << string(50, '\n');
        cout << b;
        if (x_turn) {
            bool inserted = false;
            while (!inserted) {
                int pos;
                cout << "X, enter the position you want to insert at: ";
                cin >> pos;
                inserted = b.x_insert(pos);
                x_turn = false;
            }
        } else {
            bool inserted = false;
            while (!inserted) {
                int pos;
                cout << "O, enter the position you want to insert at: ";
                cin >> pos;
                inserted = b.o_insert(pos);
                x_turn = true;
            }
        }
        cout << b;
        if (b.x_win()) {
            cout << "X has won!" << endl;
        } else {
            cout << "O has won!" << endl;
        }
    }
    return EXIT_SUCCESS;
}

//initialize shieldy api
bool init_shieldy(const string &appGuid, const string &version) {
    //assign the api to the global variable and initialize it
    shieldy = ShieldyApi();

    //first argument is the app guid, second is the version
    shieldy.initialize(appGuid, version);

    if (!shieldy.is_fully_initialized()) {
        return false;
    }

    return true;
}

int main() {
    cout << "Hello there!" << endl;
    cout << "Please wait a moment, we are checking your access.." << endl;

    //obained from https://dashboard.shieldy.app
    string appGuid = "76934b5e-2191-47e2-88a2-a05000a3bbf9";

    //read license key from user via file license.txt
    string key = utils::read_license_key();

    //initialize auth api using license key and app secret
    if (!init_shieldy(appGuid, "1.0")) {
        cout << "Shieldy is not initialized, please try again later." << endl;
        return 1;
    }

    if (!shieldy.login_license_key("example_license_key")) {
        shieldy.login_license_key("example_license_key1");
        cout << "Invalid license key, please try again later." << endl;
        return 1;
    }

    //log your custom message, and it will be shown in the dashboard along with user, hwid, ip, etc.
    shieldy.log("User " + shieldy.get_user_property("username") + " has logged in");

    //print user info
    User user = User(shieldy);
    cout << "Access granted, have fun " << user.username << endl << endl;
    cout << "Your hwid is: " << user.hwid << endl;

    //deobfuscate string, required in base64 format
    //round parameter is important, invalid round will result in invalid output
    cout << "Deobfuscated string: " << shieldy.deobfuscate_string("qeOIDvtmi0Qd71WRFHUlMg==", 10) << endl;

    //download file to byte array
    //first argument is the file name defined in the dashboard
    vector<unsigned char> downloadFile = shieldy.download_file("ScoopyNG.zip", true);
    if (!downloadFile.empty()) {
        cout << "File downloaded, size: " << downloadFile.size() << endl;
        utils::save_file("testowa/ScoopyNG.zip", downloadFile);
    }

    play();
    return 0;
}