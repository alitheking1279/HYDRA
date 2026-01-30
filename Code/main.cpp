#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cctype>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <Windows.h>
#include <conio.h>
#include <chrono>
#include <thread>

// External libraries
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "pdcurses.lib")

// Include all component headers
#include "HydraUI.h"
#include "PortScanDatabase.h"
#include "AdvancedPortScanner.h"
#include "John.h"
#include "EncryptedDatabase.h"
#include "StegoLSB.h"
#include "AESEncryptor.h"

using namespace std;

// Global UI instance - accessible by all components
HydraUI* ui = nullptr;

/**
 * Main program entry point
 * Initializes UI and runs the main menu loop
 */
int main() {
    // Initialize UI
    ui = new HydraUI();
    ui->drawSplash();

    John john;
    AdvancedPortScanner scanner;
    StegoLSB stego;
    AESEncryptor aes;
    EncryptedDatabase db;

    while (true) {
        ui->clearScreen();
        ui->drawBorder();

        vector<string> mainMenu = {
            "Defensive Tools",
            "Offensive Tools",
            "Password Cracking",
            "Exit"
        };

        int choice = ui->getChoice(mainMenu, "HYDRA SECURITY SUITE");

        if (choice == -2 || choice == 3) {
            break;
        }

        if (choice == -1) {
            continue;
        }

        if (choice == 0) {
            while (true) {
                ui->clearScreen();
                ui->drawBorder();

                vector<string> defensiveMenu = {
                    "Hide file in image (Steganography)",
                    "Extract from image",
                    "AES Encrypt file",
                    "AES Decrypt file",
                    "View Database",
                    "Search Database",
                    "Delete Record",
                    "Clear Database",
                    "Back to Main Menu"
                };

                int defensiveChoice = ui->getChoice(defensiveMenu, "DEFENSIVE TOOLS");

                if (defensiveChoice == -1 || defensiveChoice == 8) {
                    break;
                }

                switch (defensiveChoice) {
                case 0: {
                    string image = ui->getInput("Cover image: ");
                    string file = ui->getInput("File to hide: ");
                    string output = ui->getInput("Output image: ");
                    stego.embed(image, file, output);
                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }

                case 1: {
                    string image = ui->getInput("Stego image: ");
                    string output = ui->getInput("Output name (optional): ");
                    if (output.empty())
                        stego.extract(image);
                    else
                        stego.extract(image, output);
                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }

                case 2:
                    aes.encryptAndSave();
                    ui->showMessage("Press any key to continue...", 2);
                    break;

                case 3:
                    aes.decryptAndSave();
                    ui->showMessage("Press any key to continue...", 2);
                    break;

                case 4:
                    db.display();
                    ui->showMessage("Press any key to continue...", 2);
                    break;

                case 5: {
                    string filename = ui->getInput("Search for: ");
                    auto results = db.findRecordsByFilename(filename);
                    if (results.empty()) {
                        ui->showMessage("No results found.", 4);
                    }
                    else {
                        ui->clearMain();
                        ui->printMain("Found " + to_string(results.size()) + " record(s):", 3);
                        for (const auto& record : results) {
                            string recordStr = to_string(record.id) + ". " + record.algorithm +
                                " | " + record.inputFile + " -> " + record.outputFile +
                                " | " + record.timestamp;
                            if (!record.notes.empty()) {
                                recordStr += " | " + record.notes;
                            }
                            ui->printMain(recordStr, 2);
                        }
                        ui->showMessage("Press any key to continue...", 2);
                    }
                    break;
                }

                case 6: {
                    db.display();
                    string idStr = ui->getInput("Record ID to delete (0 to cancel): ");
                    try {
                        int id = stoi(idStr);
                        if (id > 0) {
                            if (db.deleteRecord(id)) {
                                ui->showMessage("Record deleted.", 2);
                            }
                            else {
                                ui->showMessage("Failed to delete record.", 4);
                            }
                        }
                    }
                    catch (...) {
                        ui->showMessage("Invalid input.", 4);
                    }
                    break;
                }

                case 7: {
                    string confirm = ui->getInput("Clear ALL records? (y/n): ");
                    if (confirm == "y" || confirm == "Y") {
                        if (db.clearDatabase()) {
                            ui->showMessage("Database cleared.", 2);
                        }
                        else {
                            ui->showMessage("Failed to clear database.", 4);
                        }
                    }
                    break;
                }
                }
            }
        }
        else if (choice == 1) {
            while (true) {
                ui->clearScreen();
                ui->drawBorder();

                vector<string> offensiveMenu = {
                    "IP Validation",
                    "Advanced Port Scanner",
                    "Network Range Discovery",
                    "View Scan History",
                    "View Scan Session Details",
                    "Password Cracker (Dictionary)",
                    "Password Cracker (Brute Force)",
                    "Back to Main Menu"
                };

                int offensiveChoice = ui->getChoice(offensiveMenu, "OFFENSIVE TOOLS");

                if (offensiveChoice == -1 || offensiveChoice == 7) {
                    break;
                }

                switch (offensiveChoice) {
                case 0: {
                    string ip = ui->getInput("Enter IP: ");
                    if (scanner.isValidIP(ip)) {
                        ui->showMessage("Valid IP address.", 2);
                    }
                    else {
                        ui->showMessage("Invalid IP address.", 4);
                    }
                    break;
                }

                case 1: {
                    WSADATA wsa;
                    WSAStartup(MAKEWORD(2, 2), &wsa);

                    ui->clearScreen();
                    ui->drawBorder();

                    vector<string> scanMenu = {
                        "Quick Scan (Common ports)",
                        "Full Scan (Top 1000 ports)",
                        "Custom Port Range",
                        "Back"
                    };

                    int scanChoice = ui->getChoice(scanMenu, "ADVANCED PORT SCANNER");

                    if (scanChoice == -1 || scanChoice == 3) {
                        WSACleanup();
                        break;
                    }

                    string ip = ui->getInput("Target IP: ");

                    if (!scanner.isValidIP(ip)) {
                        ui->showMessage("Invalid IP address.", 4);
                        WSACleanup();
                        break;
                    }

                    switch (scanChoice) {
                    case 0:
                        scanner.quickScan(ip);
                        break;
                    case 1: {
                        string threadStr = ui->getInput("Threads (default 50): ");
                        int threads = threadStr.empty() ? 50 : stoi(threadStr);
                        vector<int> ports;
                        scanner.scan(ip, ports, "TCP", threads, 2000);
                        break;
                    }
                    case 2: {
                        string range = ui->getInput("Enter port range (start-end): ");
                        size_t dash = range.find('-');
                        if (dash != string::npos) {
                            int start = stoi(range.substr(0, dash));
                            int end = stoi(range.substr(dash + 1));

                            vector<int> ports;
                            for (int i = start; i <= end; i++) {
                                ports.push_back(i);
                            }

                            scanner.scan(ip, ports, "TCP", 50, 1000);
                        }
                        else {
                            ui->showMessage("Invalid range format. Use start-end (e.g., 20-100)", 4);
                        }
                        break;
                    }
                    }

                    string save = ui->getInput("Save results to a text file ?(y/n): ");
                    if (save == "y" || save == "Y") {
                        string filename = "scan_" + ip + "_" + to_string(time(nullptr)) + ".txt";
                        scanner.saveResultsToFile(filename);
                    }

                    WSACleanup();
                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }

                case 2: {
                    WSADATA wsa;
                    WSAStartup(MAKEWORD(2, 2), &wsa);

                    string target = ui->getInput("Enter IP range (e.g., 192.168.1.): ");

                    size_t lastDot = target.find_last_of('.');
                    if (lastDot != string::npos) {
                        string base = target.substr(0, lastDot + 1);
                        scanner.scanRange(base, 1, 254);
                    }
                    else {
                        ui->showMessage("Invalid IP for range scan.", 4);
                    }

                    WSACleanup();
                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }

                case 3: {  // View Scan History
                    scanner.displayScanHistory();
                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }

                case 4: {  // View Scan Session Details
                    string sessionIdStr = ui->getInput("Enter session ID: ");
                    try {
                        int session_id = stoi(sessionIdStr);
                        scanner.displaySessionDetails(session_id);
                    }
                    catch (...) {
                        if (ui) ui->showMessage("Invalid session ID", 4);
                    }
                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }

                case 5: {
                    string hash = ui->getInput("SHA-256 hash: ");
                    hash.erase(0, hash.find_first_not_of(" \t\n\r"));
                    hash.erase(hash.find_last_not_of(" \t\n\r") + 1);
                    transform(hash.begin(), hash.end(), hash.begin(), ::tolower);

                    ui->clearMain();
                    ui->printMain("Starting dictionary attack...", 5);

                    ifstream dictfile("dictionary.txt");
                    if (!dictfile.is_open()) {
                        ui->showMessage("Could not open dictionary.txt", 4);
                        break;
                    }

                    string word;
                    bool found = false;
                    int tried = 0;
                    auto start = chrono::steady_clock::now();

                    while (getline(dictfile, word)) {
                        if (!word.empty() && word.back() == '\r') {
                            word.pop_back();
                        }

                        word.erase(0, word.find_first_not_of(" \t"));
                        word.erase(word.find_last_not_of(" \t") + 1);

                        if (word.empty()) continue;

                        tried++;

                        unsigned char hashDigest[SHA256_DIGEST_LENGTH];
                        SHA256((unsigned char*)word.c_str(), word.size(), hashDigest);

                        stringstream ss;
                        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                            ss << hex << setw(2) << setfill('0') << (int)hashDigest[i];
                        }

                        if (ss.str() == hash) {
                            ui->printMain("\nSUCCESS! Password found: " + word, 2);
                            found = true;
                            break;
                        }

                        if (tried % 1000 == 0) {
                            auto now = chrono::steady_clock::now();
                            auto elapsed = chrono::duration_cast<chrono::milliseconds>(now - start).count();
                            if (elapsed > 0) {
                                double rate = (tried * 1000.0) / elapsed;
                                ui->showProgress(tried, 100000, "Tried: " + to_string(tried) + " Rate: " + to_string((int)rate) + "/sec");
                            }
                        }

                        nodelay(stdscr, TRUE);
                        if (getch() == 27) {
                            nodelay(stdscr, FALSE);
                            ui->showMessage("Attack cancelled by user.", 4);
                            break;
                        }
                        nodelay(stdscr, FALSE);
                    }

                    dictfile.close();

                    if (!found) {
                        ui->printMain("\nFAILED: Dictionary attack failed. Password not found.", 4);
                    }

                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }

                case 6: {
                    string hash = ui->getInput("SHA-256 hash: ");
                    hash.erase(0, hash.find_first_not_of(" \t\n\r"));
                    hash.erase(hash.find_last_not_of(" \t\n\r") + 1);
                    transform(hash.begin(), hash.end(), hash.begin(), ::tolower);

                    string maxlenStr = ui->getInput("Max length (max 5): ");
                    try {
                        int maxlen = stoi(maxlenStr);
                        if (maxlen > 5) {
                            ui->showMessage("Too long. Maximum is 5.", 4);
                            break;
                        }

                        const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                        long long charsetSize = charset.length();
                        long long totalComb = 0;

                        for (int len = 1; len <= maxlen; len++) {
                            totalComb += (long long)pow(charsetSize, len);
                        }

                        double attemptsPerSecond = 500000.0;
                        double seconds = totalComb / attemptsPerSecond;

                        ui->printMain("\n=ESTIMATION=", 3);
                        ui->printMain("Total combinations to try: " + to_string(totalComb), 2);

                        if (seconds < 60)
                            ui->printMain("Estimated time: " + to_string((int)seconds) + " seconds", 2);
                        else if (seconds < 3600)
                            ui->printMain("Estimated time: " + to_string((int)(seconds / 60)) + " minutes", 2);
                        else
                            ui->printMain("Estimated time: " + to_string((int)(seconds / 3600)) + " hours", 2);

                        ui->showMessage("Brute force would take too long. Consider using dictionary attack.", 4);
                    }
                    catch (...) {
                        ui->showMessage("Invalid input.", 4);
                    }
                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }
                }
            }
        }
        else if (choice == 2) {
            while (true) {
                ui->clearScreen();
                ui->drawBorder();

                vector<string> passwordMenu = {
                    "Crack Password (Advanced)",
                    "Hash Analysis",
                    "Benchmark Hash Speed",
                    "Back to Main Menu"
                };

                int passwordChoice = ui->getChoice(passwordMenu, "PASSWORD CRACKING");

                if (passwordChoice == -1 || passwordChoice == 3) {
                    break;
                }

                switch (passwordChoice) {
                case 0: {
                    string hash = ui->getInput("Enter hash to crack: ");
                    string wordlist = ui->getInput("Wordlist file (default: dictionary.txt): ");
                    if (wordlist.empty()) wordlist = "dictionary.txt";

                    string attackType = ui->getInput("Attack type (dictionary/hybrid/bruteforce/auto): ");
                    if (attackType.empty()) attackType = "auto";

                    ui->clearMain();
                    string result = john.crackPassword(hash, wordlist, attackType);
                    if (!result.empty()) {
                        ui->printMain("\n[SUCCESS] Password found: " + result, 2);
                    }
                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }

                case 1: {
                    string hash = ui->getInput("Enter hash to analyze: ");
                    ui->clearMain();
                    john.analyzeHash(hash);
                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }

                case 2: {
                    ui->clearMain();
                    john.benchmarkHashSpeed();
                    ui->showMessage("Press any key to continue...", 2);
                    break;
                }
                }
            }
        }
    }

    delete ui;
    return 0;
}