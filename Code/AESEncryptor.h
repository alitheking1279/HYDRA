#ifndef AES_ENCRYPTOR_H
#define AES_ENCRYPTOR_H

#include <string>
#include <vector>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "EncryptedDatabase.h"

// Forward declaration
class HydraUI;
extern HydraUI* ui;
extern EncryptedDatabase db;

/**
 * AES-256-GCM file encryption/decryption with password-based key derivation
 * Uses PBKDF2 for key derivation and authenticated encryption (GCM mode)
 */
class AESEncryptor {
private:
    static void printOpenSSLErrors(const char* msg) {
        if (ui) {
            ui->printMain("[ERROR] " + string(msg), 4);
        }
    }

    static std::vector<unsigned char> readFile(const std::string& fileName) {
        std::ifstream fin(fileName, std::ios::binary | std::ios::ate);
        if (!fin) {
            if (ui) {
                ui->showMessage("Cannot open file: " + fileName, 4);
            }
            return {};
        }

        std::streamsize size = fin.tellg();
        if (size <= 0) {
            if (ui) {
                ui->showMessage("File is empty: " + fileName, 4);
            }
            return {};
        }

        fin.seekg(0, std::ios::beg);
        std::vector<unsigned char> data(size);

        if (!fin.read((char*)data.data(), size)) {
            if (ui) {
                ui->showMessage("Failed to read file: " + fileName, 4);
            }
            return {};
        }

        return data;
    }

    static std::string getFileExtension(const std::string& filename) {
        size_t dotPos = filename.find_last_of('.');
        if (dotPos == std::string::npos) return "";
        return filename.substr(dotPos + 1);
    }

    static bool deriveKeyFromPassword(const std::string& password,
        unsigned char* salt, int saltLen,
        unsigned char* key, int keyLen = 32,
        int iterations = 20000) {
        return PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
            salt, saltLen, iterations,
            EVP_sha256(), keyLen, key) == 1;
    }

    static void generateRandomBytes(unsigned char* buffer, size_t size) {
        if (!RAND_bytes(buffer, size)) {
            if (ui) {
                ui->showMessage("Failed to generate random bytes", 4);
            }
        }
    }

public:
    AESEncryptor() = default;

    void encryptFile(const std::string& inputFile, const std::string& outputFile) {
        try {
            std::vector<unsigned char> fileData = readFile(inputFile);
            if (fileData.empty()) {
                return;
            }

            std::string password;
            if (ui) {
                password = ui->getInput("Enter password for encryption: ");
            }

            if (password.empty()) {
                if (ui) {
                    ui->showMessage("Password cannot be empty", 4);
                }
                return;
            }
            EncryptedDatabase db;
            db.addRecord("AES-256", inputFile, outputFile, password);

            unsigned char salt[16];
            unsigned char iv[12];
            unsigned char key[32];
            unsigned char tag[16];

            generateRandomBytes(salt, sizeof(salt));
            generateRandomBytes(iv, sizeof(iv));

            if (!deriveKeyFromPassword(password, salt, sizeof(salt), key)) {
                if (ui) {
                    ui->showMessage("Key derivation failed", 4);
                }
                return;
            }

            std::string ext = getFileExtension(inputFile);
            uint8_t extLen = static_cast<uint8_t>(ext.size());

            std::vector<unsigned char> combined;
            combined.reserve(1 + extLen + fileData.size());
            combined.push_back(extLen);
            combined.insert(combined.end(), ext.begin(), ext.end());
            combined.insert(combined.end(), fileData.begin(), fileData.end());

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                if (ui) {
                    ui->showMessage("Failed to create encryption context", 4);
                }
                return;
            }

            if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Failed to initialize encryption", 4);
                }
                return;
            }

            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL)) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Failed to set IV length", 4);
                }
                return;
            }

            if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Failed to set key and IV", 4);
                }
                return;
            }

            std::vector<unsigned char> cipherText(combined.size() + EVP_MAX_BLOCK_LENGTH);
            int outLen = 0, totalLen = 0;

            if (!EVP_EncryptUpdate(ctx, cipherText.data(), &outLen,
                combined.data(), combined.size())) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Encryption failed", 4);
                }
                return;
            }
            totalLen = outLen;

            if (!EVP_EncryptFinal_ex(ctx, cipherText.data() + totalLen, &outLen)) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Encryption finalization failed", 4);
                }
                return;
            }
            totalLen += outLen;
            cipherText.resize(totalLen);

            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag)) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Failed to get authentication tag", 4);
                }
                return;
            }

            EVP_CIPHER_CTX_free(ctx);

            std::ofstream fout(outputFile, std::ios::binary);
            if (!fout) {
                if (ui) {
                    ui->showMessage("Cannot create output file: " + outputFile, 4);
                }
                return;
            }

            fout.write(reinterpret_cast<char*>(salt), sizeof(salt));
            fout.write(reinterpret_cast<char*>(iv), sizeof(iv));
            fout.write(reinterpret_cast<char*>(cipherText.data()), cipherText.size());
            fout.write(reinterpret_cast<char*>(tag), sizeof(tag));
            fout.close();

            if (ui) {
                ui->printMain("Encryption successful!", 2);
                ui->printMain("Original file: " + inputFile + " (" + to_string(fileData.size()) + " bytes)", 2);
                ui->printMain("Encrypted file: " + outputFile + " (" +
                    to_string(16 + 12 + cipherText.size() + 16) + " bytes)", 2);
            }

        }
        catch (const std::exception& e) {
            if (ui) {
                ui->showMessage("Encryption failed: " + string(e.what()), 4);
            }
            return;
        }
    }

    void decryptFile(const std::string& inputFile, const std::string& userOutputName = "") {
        try {
            std::vector<unsigned char> encryptedData = readFile(inputFile);
            if (encryptedData.empty()) {
                return;
            }

            if (encryptedData.size() < 45) {
                if (ui) {
                    ui->showMessage("File too small or corrupted", 4);
                }
                return;
            }

            size_t offset = 0;
            unsigned char salt[16];
            unsigned char iv[12];
            unsigned char tag[16];

            memcpy(salt, encryptedData.data() + offset, sizeof(salt));
            offset += sizeof(salt);

            memcpy(iv, encryptedData.data() + offset, sizeof(iv));
            offset += sizeof(iv);

            size_t ciphertextSize = encryptedData.size() - offset - sizeof(tag);

            if (ciphertextSize <= 0) {
                if (ui) {
                    ui->showMessage("No ciphertext found", 4);
                }
                return;
            }

            std::vector<unsigned char> cipherText(ciphertextSize);
            memcpy(cipherText.data(), encryptedData.data() + offset, ciphertextSize);
            offset += ciphertextSize;

            memcpy(tag, encryptedData.data() + offset, sizeof(tag));

            std::string password;
            if (ui) {
                password = ui->getInput("Enter password for decryption: ");
            }

            if (password.empty()) {
                if (ui) {
                    ui->showMessage("Password cannot be empty", 4);
                }
                return;
            }

            unsigned char key[32];
            if (!deriveKeyFromPassword(password, salt, sizeof(salt), key)) {
                if (ui) {
                    ui->showMessage("Key derivation failed (wrong password?)", 4);
                }
                return;
            }

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                if (ui) {
                    ui->showMessage("Failed to create decryption context", 4);
                }
                return;
            }

            if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Failed to initialize decryption", 4);
                }
                return;
            }

            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL)) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Failed to set IV length", 4);
                }
                return;
            }

            if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Failed to set key and IV", 4);
                }
                return;
            }

            std::vector<unsigned char> plainText(cipherText.size());
            int outLen = 0;

            if (!EVP_DecryptUpdate(ctx, plainText.data(), &outLen,
                cipherText.data(), cipherText.size())) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Decryption failed", 4);
                }
                return;
            }

            int totalLen = outLen;

            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag)) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Failed to set authentication tag", 4);
                }
                return;
            }

            if (!EVP_DecryptFinal_ex(ctx, plainText.data() + totalLen, &outLen)) {
                EVP_CIPHER_CTX_free(ctx);
                if (ui) {
                    ui->showMessage("Decryption failed (wrong password or corrupted data)", 4);
                }
                return;
            }

            totalLen += outLen;
            plainText.resize(totalLen);
            EVP_CIPHER_CTX_free(ctx);

            if (plainText.empty()) {
                if (ui) {
                    ui->showMessage("Decrypted data is empty", 4);
                }
                return;
            }

            size_t plainOffset = 0;
            uint8_t extLen = plainText[plainOffset];
            plainOffset += 1;

            std::string ext;
            if (extLen > 0) {
                if (plainOffset + extLen > plainText.size()) {
                    if (ui) {
                        ui->showMessage("Corrupted data: extension length mismatch", 4);
                    }
                    return;
                }
                ext = std::string(plainText.begin() + plainOffset,
                    plainText.begin() + plainOffset + extLen);
                plainOffset += extLen;
            }

            std::vector<unsigned char> fileData(plainText.begin() + plainOffset, plainText.end());

            std::string finalOutputFile;

            if (!userOutputName.empty()) {
                size_t dotPos = userOutputName.find_last_of('.');
                if (dotPos != std::string::npos && dotPos != 0) {
                    finalOutputFile = userOutputName;
                }
                else {
                    finalOutputFile = userOutputName;
                    if (!ext.empty()) {
                        finalOutputFile += "." + ext;
                    }
                }
            }
            else {
                std::string baseName = inputFile;
                size_t dotPos = baseName.find_last_of('.');

                if (dotPos != std::string::npos) {
                    std::string inputExt = baseName.substr(dotPos);
                    if (inputExt == ".enc" || inputExt == ".ENC") {
                        baseName = baseName.substr(0, dotPos);
                    }
                }

                finalOutputFile = baseName;

                if (!ext.empty()) {
                    finalOutputFile += "." + ext;
                }
            }

            std::ofstream fout(finalOutputFile, std::ios::binary);
            if (!fout) {
                if (ui) {
                    ui->showMessage("Cannot create output file: " + finalOutputFile, 4);
                }
                return;
            }

            fout.write(reinterpret_cast<char*>(fileData.data()), fileData.size());
            fout.close();

            if (ui) {
                ui->printMain("Decryption successful!", 2);
                ui->printMain("Decrypted file saved as: " + finalOutputFile + " (" +
                    to_string(fileData.size()) + " bytes)", 2);
                if (!ext.empty()) {
                    ui->printMain("Original extension restored: ." + ext, 2);
                }
            }

        }
        catch (const std::exception& e) {
            if (ui) {
                ui->showMessage("Decryption failed: " + string(e.what()), 4);
            }
            return;
        }
    }

    void decryptAndSave() {
        std::string inputFile, outputFile;

        if (ui) {
            inputFile = ui->getInput("Enter file to decrypt: ");
            outputFile = ui->getInput("Enter output file name (without extension, original extension will be added automatically): ");
        }

        if (!outputFile.empty() && outputFile.back() == '\n') {
            outputFile.pop_back();
        }

        if (!outputFile.empty() && outputFile.back() == '\r') {
            outputFile.pop_back();
        }

        decryptFile(inputFile, outputFile);
    }

    void encryptAndSave() {
        std::string inputFile, outputFile;

        if (ui) {
            inputFile = ui->getInput("Enter file to encrypt: ");
            outputFile = ui->getInput("Enter output file name (without extension, .enc will be added): ");
        }

        if (!outputFile.empty() && outputFile.find('.') == std::string::npos) {
            outputFile += ".enc";
        }

        encryptFile(inputFile, outputFile);
    }
};
#endif // AES_ENCRYPTOR_H