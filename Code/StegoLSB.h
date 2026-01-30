#ifndef STEGO_LSB_H
#define STEGO_LSB_H

#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <opencv2/opencv.hpp>
#include "zlib/zlib.h"
#include "EncryptedDatabase.h"

// Forward declaration
class HydraUI;
extern HydraUI* ui;
extern EncryptedDatabase db;

/**
 * Least Significant Bit (LSB) steganography implementation
 * Hides files inside images using zlib compression and custom header format
 */
class StegoLSB {
private:
    static void validateCompressedSize(uint32_t compSize, const cv::Mat& img, int lsb) {
        if (compSize == 0) {
            return;
        }

        if (compSize > 100 * 1024 * 1024) {
            return;
        }

        size_t maxCapacity = (size_t)img.rows * img.cols * img.channels() * lsb;
        size_t requiredBits = (4 + compSize) * 8;
        if (requiredBits > maxCapacity) {
            return;
        }
    }

public:
    StegoLSB() = default;

    void showCapacity(const std::string& imagePath, int lsb = 1) {
        cv::Mat img = cv::imread(imagePath);
        size_t capacity_bytes = (img.rows * img.cols * img.channels() * lsb) / 8;

        if (ui) {
            ui->printMain("Image can hide up to " + to_string(capacity_bytes) +
                " bytes with LSB=" + to_string(lsb), 2);
        }
    }

    std::vector<unsigned char> readFile(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) {
            return {};
        }

        std::streamsize size = f.tellg();
        if (size <= 0) {
            return {};
        }
        f.seekg(0);
        std::vector<unsigned char> data(size);

        if (!f.read((char*)data.data(), size)) {
            return {};
        }

        return data;
    }

    std::string getExt(const std::string& p) {
        size_t pos = p.find_last_of('.');
        if (pos == std::string::npos || pos == p.length() - 1) {
            return "";
        }
        return p.substr(pos + 1);
    }

    std::vector<unsigned char> makePayload(
        const std::vector<unsigned char>& data,
        const std::string& ext)
    {
        if (ext.size() > 255) {
            return {};
        }

        std::vector<unsigned char> out;

        out.push_back(0xDE);
        out.push_back(0xAD);

        out.push_back((unsigned char)ext.size());
        out.insert(out.end(), ext.begin(), ext.end());

        uint32_t s = (uint32_t)data.size();
        out.push_back((s >> 24) & 0xFF);
        out.push_back((s >> 16) & 0xFF);
        out.push_back((s >> 8) & 0xFF);
        out.push_back(s & 0xFF);

        out.insert(out.end(), data.begin(), data.end());

        return out;
    }

    std::vector<unsigned char> compressPayload(const std::vector<unsigned char>& p) {
        if (p.empty()) {
            return {};
        }

        uLongf bound = compressBound(p.size());
        std::vector<unsigned char> out(bound);

        int r = compress(out.data(), &bound, p.data(), p.size());
        if (r != Z_OK) {
            return {};
        }

        out.resize(bound);
        return out;
    }

    std::vector<unsigned char> decompressPayload(const std::vector<unsigned char>& compressedData) {
        if (compressedData.empty()) {
            return {};
        }

        uLongf destLen = compressedData.size() * 10;
        std::vector<unsigned char> decompressed(destLen);
        int r = Z_BUF_ERROR;
        int attempts = 0;

        while (r == Z_BUF_ERROR && attempts < 5) {
            r = uncompress(decompressed.data(), &destLen,
                compressedData.data(), compressedData.size());

            if (r == Z_BUF_ERROR) {
                destLen *= 2;
                decompressed.resize(destLen);
                attempts++;
            }
        }
        if (r != Z_OK) {
            return {};
        }
        decompressed.resize(destLen);
        return decompressed;
    }

    bool canFit(const cv::Mat& img, size_t bytes, int lsb = 1) {
        if (img.empty() || lsb <= 0 || lsb > 8) {
            return false;
        }

        size_t cap = (size_t)img.rows * img.cols * img.channels() * lsb;
        return (bytes * 8) <= cap;
    }

    void embedBits(cv::Mat& img, const std::vector<unsigned char>& data, int lsb) {
        if (lsb <= 0 || lsb > 8) return;
        if (img.empty()) return;
        if (data.empty()) return;

        size_t totalBits = data.size() * 8;
        size_t idx = 0;

        for (int i = 0; i < img.rows && idx < totalBits; i++) {
            for (int j = 0; j < img.cols && idx < totalBits; j++) {
                cv::Vec3b& px = img.at<cv::Vec3b>(i, j);

                for (int c = 0; c < img.channels() && idx < totalBits; c++) {
                    for (int b = 0; b < lsb && idx < totalBits; b++) {
                        px[c] &= ~(1 << b);
                        size_t byteIdx = idx / 8;
                        size_t bitIdx = 7 - (idx % 8);

                        if (byteIdx >= data.size()) {
                            return;
                        }

                        unsigned char value = (data[byteIdx] >> bitIdx) & 1;
                        px[c] |= (value << b);
                        idx++;
                    }
                }
            }
        }
    }

    std::vector<unsigned char> extractBits(const cv::Mat& img, size_t bytes, int lsb) {
        if (img.empty()) return {};
        if (lsb <= 0 || lsb > 8) return {};
        if (bytes == 0) return {};

        std::vector<unsigned char> out(bytes, 0);
        size_t totalBits = bytes * 8;
        size_t idx = 0;

        for (int i = 0; i < img.rows && idx < totalBits; i++) {
            for (int j = 0; j < img.cols && idx < totalBits; j++) {
                cv::Vec3b px = img.at<cv::Vec3b>(i, j);

                for (int c = 0; c < img.channels() && idx < totalBits; c++) {
                    for (int b = 0; b < lsb && idx < totalBits; b++) {
                        unsigned char bit = (px[c] >> b) & 1;
                        size_t byteIdx = idx / 8;
                        size_t bitPos = 7 - (idx % 8);

                        if (byteIdx >= out.size()) {
                            return {};
                        }

                        out[byteIdx] |= (bit << bitPos);
                        idx++;
                    }
                }
            }
        }

        return out;
    }
    void embed(const std::string& imagePath,
        const std::string& payloadPath,
        const std::string& outImage,
        int lsb = 1) {

        if (lsb < 1 || lsb > 8) {
            if (ui) {
                ui->showMessage("LSB must be between 1 and 8", 4);
            }
            return;
        }

        cv::Mat img = cv::imread(imagePath, cv::IMREAD_COLOR);
        if (img.empty()) {
            if (ui) {
                ui->showMessage("Failed to load image: " + imagePath, 4);
            }
            return;
        }

        auto fileData = readFile(payloadPath);
        if (fileData.empty()) {
            if (ui) {
                ui->showMessage("Payload file is empty: " + payloadPath, 4);
            }
            return;
        }

        auto ext = getExt(payloadPath);
        auto payload = makePayload(fileData, ext);
        if (payload.empty()) {
            if (ui) {
                ui->showMessage("Failed to create payload", 4);
            }
            return;
        }

        auto compressed = compressPayload(payload);
        if (compressed.empty()) {
            if (ui) {
                ui->showMessage("Failed to compress payload", 4);
            }
            return;
        }

        uint32_t compSize = (uint32_t)compressed.size();
        validateCompressedSize(compSize, img, lsb);

        std::vector<unsigned char> finalData;
        finalData.push_back((compSize >> 24) & 0xFF);
        finalData.push_back((compSize >> 16) & 0xFF);
        finalData.push_back((compSize >> 8) & 0xFF);
        finalData.push_back(compSize & 0xFF);
        finalData.insert(finalData.end(), compressed.begin(), compressed.end());

        if (!canFit(img, finalData.size(), lsb)) {
            if (ui) {
                ui->showMessage("Payload too large for image. Try increasing LSB or using a larger image.", 4);
            }
            return;
        }

        if (ui) {
            ui->printStatus("Embedding data into image...", 5);
        }

        embedBits(img, finalData, lsb);

        if (!cv::imwrite(outImage, img)) {
            if (ui) {
                ui->showMessage("Failed to save output image: " + outImage, 4);
            }
            return;
        }

        if (ui) {
            ui->clearMain();
            ui->printMain("Successfully embedded '" + payloadPath + "' into '" + outImage + "'", 2);
            ui->printMain("Original size: " + to_string(fileData.size()) + " bytes", 2);
            ui->printMain("Compressed size: " + to_string(compSize) + " bytes", 2);
            ui->printMain("Total embedded: " + to_string(finalData.size()) + " bytes", 2);
            
        }
        EncryptedDatabase db;
        db.addRecord("Steganography",imagePath,outImage,payloadPath);
    }

    void extract(const std::string& imagePath,
        const std::string& outputBaseName = "restored") {

        cv::Mat img = cv::imread(imagePath, cv::IMREAD_COLOR);
        if (img.empty()) {
            if (ui) {
                ui->showMessage("Failed to load image: " + imagePath, 4);
            }
            return;
        }

        if (ui) {
            ui->printStatus("Extracting size header...", 5);
        }

        auto sizeBytes = extractBits(img, 4, 1);
        if (sizeBytes.empty()) {
            if (ui) {
                ui->showMessage("Failed to extract size header", 4);
            }
            return;
        }

        uint32_t compSize =
            (sizeBytes[0] << 24) |
            (sizeBytes[1] << 16) |
            (sizeBytes[2] << 8) |
            sizeBytes[3];

        if (ui) {
            ui->printStatus("Extracting compressed data...", 5);
        }

        auto allExtracted = extractBits(img, 4 + compSize, 1);
        if (allExtracted.empty()) {
            if (ui) {
                ui->showMessage("Failed to extract compressed data", 4);
            }
            return;
        }

        if (allExtracted.size() < 4 + compSize) {
            if (ui) {
                ui->showMessage("Extracted data smaller than expected", 4);
            }
            return;
        }

        std::vector<unsigned char> compressed(allExtracted.begin() + 4, allExtracted.end());

        if (ui) {
            ui->printStatus("Decompressing...", 5);
        }

        auto decompressed = decompressPayload(compressed);
        if (decompressed.empty()) {
            if (ui) {
                ui->showMessage("Failed to decompress payload", 4);
            }
            return;
        }

        if (decompressed.size() < 2) {
            if (ui) {
                ui->showMessage("Decompressed payload too small", 4);
            }
            return;
        }

        if (decompressed[0] != 0xDE || decompressed[1] != 0xAD) {
            if (ui) {
                ui->showMessage("Invalid magic bytes in decompressed payload", 4);
            }
            return;
        }

        if (decompressed.size() < 3) {
            if (ui) {
                ui->showMessage("Payload too small for extension", 4);
            }
            return;
        }

        size_t extLen = decompressed[2];
        if (3 + extLen > decompressed.size()) {
            if (ui) {
                ui->showMessage("Extension length exceeds payload size", 4);
            }
            return;
        }

        std::string ext(decompressed.begin() + 3,
            decompressed.begin() + 3 + extLen);

        size_t sizePos = 3 + extLen;
        if (sizePos + 4 > decompressed.size()) {
            if (ui) {
                ui->showMessage("File size position out of bounds", 4);
            }
            return;
        }

        uint32_t origSize =
            (decompressed[sizePos] << 24) |
            (decompressed[sizePos + 1] << 16) |
            (decompressed[sizePos + 2] << 8) |
            decompressed[sizePos + 3];

        size_t dataStart = sizePos + 4;
        if (dataStart + origSize > decompressed.size()) {
            if (ui) {
                ui->showMessage("File data exceeds payload bounds", 4);
            }
            return;
        }

        std::vector<unsigned char> fileData(
            decompressed.begin() + dataStart,
            decompressed.begin() + dataStart + origSize
        );

        std::string outputFilename = outputBaseName;
        if (!ext.empty()) {
            outputFilename += "." + ext;
        }
        else {
            outputFilename += ".bin";
        }

        std::ofstream out(outputFilename, std::ios::binary);
        if (!out) {
            if (ui) {
                ui->showMessage("Failed to create output file: " + outputFilename, 4);
            }
            return;
        }

        out.write((char*)fileData.data(), fileData.size());
        out.close();

        if (ui) {
            ui->clearMain();
            ui->printMain("Successfully extracted file to: " + outputFilename, 2);
            ui->printMain("File size: " + to_string(fileData.size()) + " bytes", 2);
        }
    }
};
#endif // STEGO_LSB_H