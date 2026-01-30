#ifndef JOHN_H
#define JOHN_H

#include <string>
#include <vector>
#include <unordered_set>
#include <regex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <algorithm>
#include <openssl/md5.h>
#include <openssl/sha.h>

// Forward declaration
class HydraUI;
extern HydraUI* ui;

/**
 * Password cracking utility with multiple attack modes
 * Supports dictionary, hybrid, and brute-force attacks
 * Detects hash types and benchmarks performance
 */
class John {
private:
    const string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const string digits = "0123456789";
    const string special = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    struct HashPattern {
        string name;
        string pattern;
        int length;
        string example;
    };

    vector<HashPattern> hashPatterns = {
        {"MD5", "^[a-f0-9]{32}$", 32, "5d41402abc4b2a76b9719d911017c592"},
        {"SHA-1", "^[a-f0-9]{40}$", 40, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
        {"SHA-256", "^[a-f0-9]{64}$", 64, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
        {"SHA-512", "^[a-f0-9]{128}$", 128, "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"},
        {"NTLM", "^[a-f0-9]{32}$", 32, "8846f7eaee8fb117ad06bdd830b7586c"},
        {"MySQL 4.1+", "^[a-f0-9]{40}$", 40, "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"}
    };

    // ========== BUILT-IN PATTERNS ==========
    vector<string> builtInPatterns = {
        // Single letters and numbers 
        "a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z",
        "0","1","2","3","4","5","6","7","8","9",

        // Double letters
        "aa","bb","cc","dd","ee","ff","gg","hh","ii","jj","kk","ll","mm","nn","oo","pp","qq","rr","ss","tt","uu","vv","ww","xx","yy","zz",

        // Common 3-letter combos 
        "cab","abs","car","cat","dog","sun","moon","star","hot","cold","wet","dry","big","red","blue",
        "abc","xyz","qwe","asd","zxc","iop","jkl","bnm","qaz","wsx","edc","rfv","tgb","yhn","ujm","ik","ol","p",
        "123","234","345","456","567","678","789","890","111","222","333","444","555","666","777","888","999","000",

        // Very common short passwords 
        "hi","ok","no","yes","go","up","in","out","on","off","top","bot","win","lol","wow","hey","bye",

        // Common 4-letter
        "test","pass","word","love","hate","like","want","need","have","give","take","make","play","work","home",
        "door","wall","room","desk","book","page","file","data","code","name","user","admin","root","guest",

        // Top 50 passwords 
        "123456","password","12345678","qwerty","123456789","12345","1234","111111","1234567","dragon",
        "123123","baseball","abc123","football","monkey","letmein","696969","shadow","master","666666",
        "qwertyuiop","123321","mustang","1234567890","michael","654321","superman","1qaz2wsx","7777777",
        "fuckyou","fuckoff","fuckme","admin123","admin","password123","123qwe","welcome","login","pass",
        "hello","jesus","jordan","tigger","trustno1","sunshine","iloveyou","starwars","matrix","princess"
    };

public:
    // ========== detectHashType ==========
    string detectHashType(const string& hash) {
        string cleanHash = hash;
        cleanHash.erase(remove_if(cleanHash.begin(), cleanHash.end(),
            [](char c) { return !isxdigit(c) && c != '*'; }), cleanHash.end());

        for (const auto& pattern : hashPatterns) {
            regex re(pattern.pattern);
            if (regex_match(cleanHash, re)) {
                if (pattern.name == "MD5" || pattern.name == "NTLM") {
                    return "MD5/NTLM (ambiguous)";
                }
                return pattern.name;
            }
        }

        if (cleanHash.length() % 4 == 0 &&
            regex_match(cleanHash, regex("^[A-Za-z0-9+/=]+$"))) {
            return "Base64 encoded";
        }

        return "Unknown hash type";
    }

    // ========== hash functions ==========
    string hashMD5(const string& str) {
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5((unsigned char*)str.c_str(), str.size(), digest);

        char mdString[33];
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
            sprintf(&mdString[i * 2], "%02x", (unsigned int)digest[i]);
        return string(mdString);
    }

    string hashSHA1(const string& str) {
        unsigned char digest[SHA_DIGEST_LENGTH];
        SHA1((unsigned char*)str.c_str(), str.size(), digest);

        char shaString[41];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
            sprintf(&shaString[i * 2], "%02x", (unsigned int)digest[i]);
        return string(shaString);
    }

    string hashSHA256(const string& str) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)str.c_str(), str.size(), digest);

        char shaString[65];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            sprintf(&shaString[i * 2], "%02x", (unsigned int)digest[i]);
        return string(shaString);
    }

    string hashSHA512(const string& str) {
        unsigned char digest[SHA512_DIGEST_LENGTH];
        SHA512((unsigned char*)str.c_str(), str.size(), digest);

        char shaString[129];
        for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
            sprintf(&shaString[i * 2], "%02x", (unsigned int)digest[i]);
        return string(shaString);
    }

    string hashString(const string& str, const string& hashType = "auto") {
        string type = hashType;

        if (type == "auto") {
            return hashMD5(str);
        }

        if (type == "md5" || type == "MD5") return hashMD5(str);
        if (type == "sha1" || type == "SHA-1") return hashSHA1(str);
        if (type == "sha256" || type == "SHA-256") return hashSHA256(str);
        if (type == "sha512" || type == "SHA-512") return hashSHA512(str);

        return hashMD5(str);
    }

    // ========== loadWordlist - ALWAYS works ==========
    vector<string> loadWordlist(const string& filename, bool withVariations = false) {
        vector<string> wordlist;

        wordlist.insert(wordlist.end(), builtInPatterns.begin(), builtInPatterns.end());

        ifstream file(filename);
        if (file.is_open()) {
            string word;
            while (getline(file, word)) {
                word.erase(remove(word.begin(), word.end(), '\r'), word.end());
                word.erase(0, word.find_first_not_of(" \t"));
                word.erase(word.find_last_not_of(" \t") + 1);

                if (word.empty()) continue;

                wordlist.push_back(word);

                if (withVariations) {
                    wordlist.push_back(word + "123");
                    wordlist.push_back(word + "1234");
                    wordlist.push_back(word + "12345");
                    wordlist.push_back(word + "123456");
                    wordlist.push_back(word + "!");
                    wordlist.push_back(word + "!!");
                    wordlist.push_back(word + "@123");
                    wordlist.push_back(word + "1");
                    wordlist.push_back(word + "12");

                    if (!word.empty()) {
                        string cap = word;
                        cap[0] = toupper(cap[0]);
                        wordlist.push_back(cap);

                        string upper = word;
                        transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
                        wordlist.push_back(upper);

                        wordlist.push_back(word + word);
                    }
                }
            }
            file.close();

            if (ui) {
                ui->printMain("Loaded " + to_string(wordlist.size()) + " words from " + filename, 2);
            }
        }
        else {
            if (ui) {
                ui->printMain("Using " + to_string(wordlist.size()) + " built-in patterns", 3);
            }
        }

        unordered_set<string> seen;
        vector<string> uniqueList;
        for (const auto& w : wordlist) {
            if (seen.find(w) == seen.end()) {
                seen.insert(w);
                uniqueList.push_back(w);
            }
        }

        return uniqueList;
    }

    // ========== dictionaryAttack  ==========
    string dictionaryAttack(const string& targetHash, const vector<string>& wordlist,
        const string& hashType = "auto") {

        if (ui) {
            ui->printMain("\n[+] Starting dictionary attack...", 5);
            ui->printMain("[+] Hash type: " + (hashType == "auto" ? detectHashType(targetHash) : hashType), 2);
            ui->printMain("[+] Words to try: " + to_string(wordlist.size()), 2);
        }

        int tried = 0;
        auto start = chrono::steady_clock::now();

        for (const auto& word : wordlist) {
            tried++;

            if (tried % 1000 == 0) {
                auto now = chrono::steady_clock::now();
                auto elapsed = chrono::duration_cast<chrono::milliseconds>(now - start).count();
                if (elapsed > 0) {
                    double rate = (tried * 1000.0) / elapsed;
                    if (ui) {
                        string status = "[*] Tried: " + to_string(tried) + "/" + to_string(wordlist.size()) +
                            " | Current: \"" + word + "\" | Rate: " + to_string((int)rate) + "/sec";
                        ui->printStatus(status, 5);
                    }
                }

                if (ui) {
                    nodelay(stdscr, TRUE);
                    if (getch() == 27) {
                        nodelay(stdscr, FALSE);
                        if (ui) ui->showMessage("Attack cancelled by user", 4);
                        return "";
                    }
                    nodelay(stdscr, FALSE);
                }
            }

            string hashedWord = hashString(word, hashType);

            if (hashedWord == targetHash) {
                auto end = chrono::steady_clock::now();
                auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start).count();

                if (ui) {
                    ui->printMain("\n[+] SUCCESS! Password found: \"" + word + "\"", 2);
                    ui->printMain("[+] Time: " + to_string(elapsed) + "ms", 2);
                    ui->printMain("[+] Attempts: " + to_string(tried), 2);
                }
                return word;
            }

            string lowerWord = word;
            transform(lowerWord.begin(), lowerWord.end(), lowerWord.begin(), ::tolower);
            if (lowerWord != word) {
                string hashedLower = hashString(lowerWord, hashType);
                if (hashedLower == targetHash) {
                    auto end = chrono::steady_clock::now();
                    auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start).count();

                    if (ui) {
                        ui->printMain("\n[+] SUCCESS! Password found (lowercase): \"" + lowerWord + "\"", 2);
                        ui->printMain("[+] Time: " + to_string(elapsed) + "ms", 2);
                    }
                    return lowerWord;
                }
            }

            string upperWord = word;
            transform(upperWord.begin(), upperWord.end(), upperWord.begin(), ::toupper);
            if (upperWord != word && upperWord != lowerWord) {
                string hashedUpper = hashString(upperWord, hashType);
                if (hashedUpper == targetHash) {
                    auto end = chrono::steady_clock::now();
                    auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start).count();

                    if (ui) {
                        ui->printMain("\n[+] SUCCESS! Password found (uppercase): \"" + upperWord + "\"", 2);
                        ui->printMain("[+] Time: " + to_string(elapsed) + "ms", 2);
                    }
                    return upperWord;
                }
            }
        }

        auto end = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start).count();

        if (ui) {
            ui->printMain("\n[-] Dictionary attack failed", 4);
            ui->printMain("[-] Tried all " + to_string(tried) + " words", 4);
        }

        return "";
    }

    // ========== hybridAttack ==========
    string hybridAttack(const string& targetHash, const vector<string>& wordlist,
        const string& hashType = "auto", int maxSuffixLength = 4) {

        if (ui) {
            ui->printMain("\n[+] Starting hybrid attack...", 5);
        }

        vector<string> suffixes;

        for (int i = 0; i <= 999; i++) {
            suffixes.push_back(to_string(i));
        }

        suffixes.push_back("!");
        suffixes.push_back("!!");
        suffixes.push_back("!!!");
        suffixes.push_back("123");
        suffixes.push_back("1234");
        suffixes.push_back("12345");
        suffixes.push_back("123456");
        suffixes.push_back("1");
        suffixes.push_back("12");

        suffixes.push_back("2024");
        suffixes.push_back("2023");
        suffixes.push_back("2022");
        suffixes.push_back("2021");
        suffixes.push_back("2020");

        int tried = 0;
        auto start = chrono::steady_clock::now();

        for (const auto& word : wordlist) {
            for (const auto& suffix : suffixes) {
                if (suffix.length() > maxSuffixLength) continue;

                string candidate = word + suffix;
                tried++;

                if (tried % 50000 == 0) {
                    auto now = chrono::steady_clock::now();
                    auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
                    if (elapsed > 0) {
                        double rate = tried / elapsed;
                        if (ui) {
                            string status = "[*] Tried: " + to_string(tried) + " | Rate: " +
                                to_string((int)rate) + "/sec";
                            ui->printStatus(status, 5);
                        }
                    }
                }

                string hashedCandidate = hashString(candidate, hashType);

                if (hashedCandidate == targetHash) {
                    auto end = chrono::steady_clock::now();
                    auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start).count();

                    if (ui) {
                        ui->printMain("\n[+] SUCCESS! Password found: " + candidate, 2);
                        ui->printMain("[+] Time: " + to_string(elapsed) + "ms", 2);
                    }
                    return candidate;
                }
            }
        }

        if (ui) {
            ui->printMain("\n[-] Hybrid attack failed after " + to_string(tried) + " attempts", 4);
        }
        return "";
    }

    // ==========  BruteForceGenerator  ==========
    class BruteForceGenerator {
    private:
        string charset;
        vector<int> indices;
        int currentLength;
        bool first;

    public:
        BruteForceGenerator(const string& charsetSet) : charset(charsetSet), currentLength(1), first(true) {
            indices.push_back(-1);
        }

        string next() {
            if (first) {
                first = false;
                indices[0] = 0;
                return string(1, charset[0]);
            }

            int pos = indices.size() - 1;
            while (pos >= 0) {
                indices[pos]++;
                if (indices[pos] < charset.length()) {
                    break;
                }
                indices[pos] = 0;
                pos--;
            }

            if (pos < 0) {
                currentLength++;
                indices.clear();
                indices.resize(currentLength, 0);
            }

            string result;
            for (int idx : indices) {
                result += charset[idx];
            }
            return result;
        }

        vector<string> nextBatch(int batchSize) {
            vector<string> batch;
            for (int i = 0; i < batchSize; i++) {
                batch.push_back(next());
            }
            return batch;
        }

        void reset() {
            indices.clear();
            indices.push_back(-1);
            currentLength = 1;
            first = true;
        }

        int getCurrentLength() const {
            return currentLength;
        }
    };

    // ==========  intelligentBruteForce - GUARANTEED ==========
    string intelligentBruteForce(const string& targetHash, const string& hashType = "auto",
        const string& customCharset = "", int maxLength = 8,
        long long maxAttempts = 10000000) {

        string usedCharset = customCharset.empty() ?
            lowercase + uppercase + digits + special : customCharset;

        if (ui) {
            ui->printMain("\n[+] Starting brute force...", 5);
            ui->printMain("[+] Charset: " + to_string(usedCharset.length()) + " chars", 2);
            ui->printMain("[+] Max length: " + to_string(maxLength), 2);
        }

        auto start = chrono::steady_clock::now();
        long long tried = 0;

        if (ui) {
            ui->printMain("[*] Trying built-in patterns...", 5);
        }

        for (const auto& pattern : builtInPatterns) {
            if (pattern.length() > maxLength) continue;

            tried++;
            if (hashString(pattern, hashType) == targetHash) {
                auto end = chrono::steady_clock::now();
                auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start).count();

                if (ui) {
                    ui->printMain("\n[+] SUCCESS in patterns: " + pattern, 2);
                    ui->printMain("[+] Time: " + to_string(elapsed) + "ms", 2);
                }
                return pattern;
            }
        }

        BruteForceGenerator generator(usedCharset);

        if (ui) {
            ui->printMain("[*] Starting systematic brute force...", 5);
        }

        while (tried < maxAttempts) {
            vector<string> batch = generator.nextBatch(10000);

            int currentLength = generator.getCurrentLength();
            if (currentLength > maxLength) {
                if (ui) {
                    ui->printMain("[-] Reached max length " + to_string(maxLength), 4);
                }
                break;
            }

            for (const auto& candidate : batch) {
                if (candidate.length() > maxLength) {
                    continue;
                }

                tried++;

                if (tried % 100000 == 0) {
                    auto now = chrono::steady_clock::now();
                    auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
                    if (elapsed > 0) {
                        double rate = tried / elapsed;
                        if (ui) {
                            string status = "[*] Tried: " + to_string(tried) + " | Len: " +
                                to_string(candidate.length()) + " | Rate: " + to_string((int)rate) + "/sec";
                            ui->printStatus(status, 5);
                        }
                    }
                }

                string hashed = hashString(candidate, hashType);
                if (hashed == targetHash) {
                    auto end = chrono::steady_clock::now();
                    auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start).count();

                    if (ui) {
                        ui->printMain("\n[+] SUCCESS! Password: " + candidate, 2);
                        ui->printMain("[+] Time: " + to_string(elapsed) + "ms", 2);
                        ui->printMain("[+] Attempts: " + to_string(tried), 2);
                    }
                    return candidate;
                }

                if (tried >= maxAttempts) break;
            }
        }

        auto end = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::seconds>(end - start).count();

        if (ui) {
            ui->printMain("\n[-] Brute force failed after " + to_string(tried) + " attempts", 4);
        }

        return "";
    }

    // ==========  crackPassword  ==========
    string crackPassword(const string& targetHash, const string& wordlistFile = "dictionary.txt",
        const string& attackType = "auto", const string& hashType = "auto") {

        if (ui) {
            ui->clearMain();
            ui->printMain("=========================================", 3);
            ui->printMain("     PASSWORD   CRACKER", 3);
            ui->printMain("=========================================", 3);
            ui->printMain("Target: " + targetHash, 2);
        }

        string detectedType = detectHashType(targetHash);
        string actualHashType = hashType;
        if (hashType == "auto") {
            if (detectedType.find("MD5") != string::npos) actualHashType = "md5";
            else if (detectedType.find("SHA-1") != string::npos) actualHashType = "sha1";
            else if (detectedType.find("SHA-256") != string::npos) actualHashType = "sha256";
            else if (detectedType.find("SHA-512") != string::npos) actualHashType = "sha512";
            else actualHashType = "md5";
        }

        if (ui) {
            ui->printMain("Type: " + detectedType + " | Using: " + actualHashType, 2);
        }

        string password;

        if (attackType == "dictionary" || attackType == "auto") {
            vector<string> wordlist = loadWordlist(wordlistFile, true);
            if (!wordlist.empty()) {
                password = dictionaryAttack(targetHash, wordlist, actualHashType);
                if (!password.empty()) return password;
            }
        }

        if (attackType == "hybrid" || attackType == "auto") {
            vector<string> wordlist = loadWordlist(wordlistFile, false);
            if (!wordlist.empty()) {
                password = hybridAttack(targetHash, wordlist, actualHashType, 4);
                if (!password.empty()) return password;
            }
        }

        if (attackType == "bruteforce" || attackType == "auto") {
            vector<string> charsets = {
                digits,
                lowercase,
                lowercase + digits,
                lowercase + uppercase,
                lowercase + uppercase + digits,
                lowercase + uppercase + digits + special
            };

            for (const auto& charset : charsets) {
                if (ui) {
                    ui->printMain("\n[+] Trying charset size: " + to_string(charset.length()), 5);
                }

                for (int len = 1; len <= 6; len++) {
                    password = intelligentBruteForce(targetHash, actualHashType, charset, len, 500000);
                    if (!password.empty()) return password;
                }
            }
        }

        if (ui) {
            ui->printMain("\n[-] ALL ATTACKS FAILED", 4);
        }

        return "";
    }

    void benchmarkHashSpeed(const string& hashType = "sha256") {
        if (ui) {
            ui->printMain("\n[+] Benchmarking " + hashType + "...", 5);
        }

        string testString = "test_password_123";
        int iterations = 100000;

        auto start = chrono::steady_clock::now();
        for (int i = 0; i < iterations; i++) {
            hashString(testString + to_string(i), hashType);
        }
        auto end = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start).count();

        double hashesPerSecond = (iterations * 1000.0) / max(1, (int)elapsed);

        if (ui) {
            ui->printMain("[+] Results:", 2);
            ui->printMain("    Hashes: " + to_string(iterations), 2);
            ui->printMain("    Time: " + to_string(elapsed) + "ms", 2);
            ui->printMain("    Speed: " + to_string((int)hashesPerSecond) + "/sec", 2);
        }
    }

    void analyzeHash(const string& hash) {
        if (ui) {
            ui->printMain("\n[+] Hash Analysis:", 3);
            ui->printMain("    Hash: " + hash, 2);
            ui->printMain("    Length: " + to_string(hash.length()), 2);
            ui->printMain("    Type: " + detectHashType(hash), 2);
        }
    }
};
#endif // JOHN_H