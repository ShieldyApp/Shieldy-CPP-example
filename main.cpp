#include <iostream>
#include <string>
#include <thread>
#include "shieldy_cpp_api.h"
#include "board.h"

ShieldyApi shieldy;

class ShieldyUser {

public:
    ShieldyUser() {

    }

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

    ShieldyUser(ShieldyApi api) {
        username = api.get_user_property("username");
        avatar = api.get_user_property("avatar");
        accessLevel = stoi(api.get_user_property("accessLevel"));
        licenseCreated = stoi(api.get_user_property("licenseCreated"));
        licenseExpiry = stoi(api.get_user_property("licenseExpiry"));
        hwidLimit = stoi(api.get_user_property("hwidLimit"));
        lastAccessDate = stoi(api.get_user_property("lastAccessDate"));
        lastAccessIp = api.get_user_property("lastAccessIp");
        files = split_string(api.get_user_property("files"), ";");
        variables = split_string(api.get_user_property("variables"), ";");
        hwid = api.get_user_property("hwid");
    }

    friend std::ostream& operator<<(std::ostream& os, const ShieldyUser& user) {
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
        for (auto &file : user.files) {
            os << file << endl;
        }
        os << "variables: " << endl;
        for (auto &variable : user.variables) {
            os << variable << endl;
        }
        os << "hwid: " << user.hwid << endl;
        os << endl;
        return os;
    }

private:
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
};

namespace utils {
    bool save_file(const std::string& path, const std::vector<unsigned char>& data) {
        try {
            std::filesystem::path file_path(path);
            std::filesystem::create_directories(file_path.parent_path());
            std::ofstream file(path, std::ios::binary | std::ios::out);
            if (!file.good()) {
                cout << "Could not create file at path: " << path << endl;
                return false;
            }

            file.write((const char*)data.data(), data.size());
            file.close();
        } catch (std::exception &e) {
            cout << "Could not create directories: " << e.what() << endl;
            return false;
        }
        return true;
    }
}

//src: https://github.com/zachbellay/tictactoe
int play() {

    auto secret = shieldy.get_secret("PerApp");
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

bool init_shieldy() {
    shieldy = ShieldyApi();
    shieldy.initialize();

    if (!shieldy.is_fully_initialized()) {
        return false;
    }

    return true;
}

int main() {
    cout << "Hello there!" << endl;
    cout << "Please wait a moment, we are checking your access.." << endl;

    if (!init_shieldy()) {
        cout << "Shieldy is not initialized, please try again later." << endl;
        return 1;
    }

    ShieldyUser user = ShieldyUser(shieldy);
    cout << "Access granted, have fun " << user.username << endl << endl;
    cout << "Your hwid is: " << user.hwid << endl;
    //you can also get hwid that way
    cout << "Your hwid is: " << shieldy.get_user_property("hwid") << endl << endl;

    vector<unsigned char> file = {};
    if (shieldy.download_file("ScoopyNG.zip", file, true)) {
        cout << "File downloaded, size: " << file.size() << endl;
        utils::save_file("testowa/ScoopyNG.zip", file);
    }
    return play();
}