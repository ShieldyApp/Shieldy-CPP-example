#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <filesystem>
#include <fstream>

#include "shieldy_api.h"
#include "game/board.h"

//global variable which allow to access the api from anywhere
using shieldy_sdk::ShieldyApi;

namespace utils {
    bool save_file(const std::string &path, const std::string &data) {
        try {
            std::filesystem::path file_path(path);
            std::filesystem::create_directories(file_path.parent_path());
            std::ofstream file(path, std::ios::binary | std::ios::out);
            if (!file.good()) {
                std::cout << "Could not create file at path: " << path << std::endl;
                return false;
            }
            file.write(data.data(), (int) data.size());
            file.close();
        } catch (std::exception &e) {
            std::cout << "Could not create directories: " << e.what() << std::endl;
            return false;
        }
        return true;
    }

    std::vector<std::string> split_string(const std::string &i_str, const std::string &i_delim) {
        std::vector<std::string> result;

        size_t found = i_str.find(i_delim);
        size_t startIndex = 0;

        while (found != std::string::npos) {
            result.emplace_back(i_str.begin() + startIndex, i_str.begin() + found);
            startIndex = found + i_delim.size();
            found = i_str.find(i_delim, startIndex);
        }
        if (startIndex != i_str.size())
            result.emplace_back(i_str.begin() + startIndex, i_str.end());
        return result;
    }

    //you can read license key from file or using gui, its only example
    std::string read_license_key() {
        std::string licenseKeyPath = "license.txt";

        std::ifstream iostream(licenseKeyPath.c_str());

        //<editor-fold desc="license file not exists">
        if (!iostream.good()) {
            std::ofstream outfile(licenseKeyPath.c_str());
            outfile << "XXXXXX-XXXXXX-XXXXX";
            outfile.close();

            std::filesystem::path p = licenseKeyPath.c_str();

            std::cout << "License key not found.\nPlease enter valid license key in 'license.txt'\n\nFile created at:\n"
                      << std::filesystem::absolute(p).string() << std::endl;
            exit(0);
        }
        //</editor-fold>
        std::stringstream buffer;
        buffer << iostream.rdbuf();

        return buffer.str();
    }

    void message_callback(int code, const char *message) {
        std::cout << "CALLBACK Message received: " << message << std::endl;
    }

    void progress_callback(float progress) {
        std::cout << "CALLBACK Progress received: " << progress << std::endl;
    }
}

namespace base {
    //src: https://github.com/zachbellay/tictactoe
    int play() {

        //late checks are recommended, to detect memory modifications
        if (!ShieldyApi::instance().attest()) {
            return -3;
        }

        int board_size;
        bool x_turn = true;

        std::cout << "2 Player Tic Tac Toe:" << std::endl;
        std::cout << "How large should the board be? (Enter a whole number): ";
        std::cin >> board_size;
        tictactoe::board board(board_size);
        while (!board.x_win() && !board.o_win()) {
            std::cout << std::string(50, '\n');
            std::cout << board;
            if (x_turn) {
                bool inserted = false;
                while (!inserted) {
                    int pos;
                    std::cout << "X, enter the position you want to insert at: ";
                    std::cin >> pos;
                    inserted = board.x_insert(pos);
                    x_turn = false;
                }
            } else {
                bool inserted = false;
                while (!inserted) {
                    int pos;
                    std::cout << "O, enter the position you want to insert at: ";
                    std::cin >> pos;
                    inserted = board.o_insert(pos);
                    x_turn = true;
                }
            }
            std::cout << board;
            if (board.x_win()) {
                std::cout << "X has won!" << std::endl;
            } else {
                std::cout << "O has won!" << std::endl;
            }
        }
        return EXIT_SUCCESS;
    }
}

bool init() {
    //obained from https://dashboard.shieldy.app
    std::string version = "1.0";
    std::string appGuid = "76934b5e-2191-47e2-88a2-a05000a3bbf9";
    std::vector<unsigned char> appSalt = {0x61, 0x66, 0xed, 0xbd, 0x36, 0xae, 0xc1, 0x1a, 0xf6,
                                          0x6e, 0x72, 0x2e, 0x40, 0xba, 0xa2, 0xc7, 0x64, 0x53,
                                          0x87, 0xf2, 0x8e, 0xfe, 0x4e, 0x60, 0xab, 0xcc, 0x45,
                                          0x47, 0x23, 0xf6, 0x43, 0x9e};

    //initialize auth api using license licenseKey and app secret
    if (!ShieldyApi::instance().initialize(appGuid, version, appSalt)) {
        std::cout << "Failed to initialize application." << std::endl;
        return false;
    }

    //read license licenseKey from user via file license.txt or use GUI
    std::string licenseKey = utils::read_license_key();

    if (!ShieldyApi::instance().authorize(licenseKey)) {
        std::cout << "Login failed" << std::endl;
        return false;
    }

    return true;
}

int main() {
    std::cout << "Hello there!" << std::endl;
    std::cout << "Please wait a moment, we are checking your access.." << std::endl;

    if (!init()) return 1;


    //log your custom message, and it will be shown in the dashboard along with user, hwid, ip, etc.
//    shieldy.log("User " + shieldy.get_license_property("username") + " has logged in | ' OR '5'='5' /*");

    //print user info
    std::cout << "Access granted, have fun! " << std::endl << std::endl;
    shieldy_sdk::License *licensePtr = ShieldyApi::instance().mLicense.get();

    std::cout << licensePtr->to_string() << std::endl;

    //deobfuscate std::string, required in base64 format
    //round parameter is important, invalid round will result in invalid output
//    std::cout << "Deobfuscated std::string: " << ShieldyApi::instance().de("qeOIDvtmi0Qd71WRFHUlMg==", 10)
//              << std::endl;

    //download file to byte array
    //first argument is the file name defined in the dashboard
    std::string downloadFile = ShieldyApi::instance().download_file("C42064CD-9E51-48EF-A871-0E0644C07582.gif");
    if (!downloadFile.empty()) {
        std::cout << "File downloaded, size: " << downloadFile.size() << std::endl;
        utils::save_file("testowa/ScoopyNG.zip", downloadFile);
    }

    base::play();
    std::cin.get();
    return 0;
}