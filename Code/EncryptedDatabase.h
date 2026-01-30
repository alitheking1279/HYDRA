#ifndef ENCRYPTED_DATABASE_H
#define ENCRYPTED_DATABASE_H

#include <string>
#include <vector>
#include "SQLite/sqlite3.h"

// Forward declaration
class HydraUI;
extern HydraUI* ui;

/**
 * SQLite database manager for encryption/steganography records
 * Tracks file operations with timestamps and metadata
 */
class EncryptedDatabase {
private:
    sqlite3* db;
    std::string dbPath;

public:
    EncryptedDatabase(const std::string& dbFile = "security_suite.db") : db(nullptr), dbPath(dbFile) {
        initializeDatabase();
    }

    ~EncryptedDatabase() {
        if (db) {
            sqlite3_close(db);
        }
    }

private:
    void initializeDatabase() {
        int rc = sqlite3_open(dbPath.c_str(), &db);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to open database: " + string(sqlite3_errmsg(db)), 4);
            }
            db = nullptr;
            return;
        }

        // Create records table if it doesn't exist
        const char* createTableSQL = R"(
            CREATE TABLE IF NOT EXISTS encryption_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                input_file TEXT NOT NULL,
                output_file TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            );
        )";

        char* errMsg = nullptr;
        rc = sqlite3_exec(db, createTableSQL, nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to create table: " + string(errMsg), 4);
            }
            sqlite3_free(errMsg);
        }

        if (ui && rc == SQLITE_OK) {
            ui->printMain("Database initialized successfully", 2);
        }
    }

public:
    bool addRecord(const std::string& algorithm, const std::string& inputFile,
        const std::string& outputFile, const std::string& notes = "") {
        if (!db) return false;

        const char* insertSQL = R"(
            INSERT INTO encryption_records (algorithm, input_file, output_file, notes)
            VALUES (?, ?, ?, ?);
        )";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to prepare statement: " + string(sqlite3_errmsg(db)), 4);
            }
            return false;
        }

        sqlite3_bind_text(stmt, 1, algorithm.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, inputFile.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, outputFile.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, notes.c_str(), -1, SQLITE_STATIC);

        rc = sqlite3_step(stmt);
        bool success = (rc == SQLITE_DONE);

        if (success && ui) {
            ui->printMain("Record added to database", 2);
        }
        else if (ui) {
            ui->printMain("Failed to add record: " + string(sqlite3_errmsg(db)), 4);
        }

        sqlite3_finalize(stmt);
        return success;
    }

    struct Record {
        int id;
        std::string algorithm;
        std::string inputFile;
        std::string outputFile;
        std::string timestamp;
        std::string notes;
    };

    std::vector<Record> getAllRecords() {
        std::vector<Record> records;
        if (!db) return records;

        const char* selectSQL = R"(
            SELECT id, algorithm, input_file, output_file, 
                   datetime(timestamp, 'localtime'), notes
            FROM encryption_records
            ORDER BY timestamp DESC;
        )";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to prepare query: " + string(sqlite3_errmsg(db)), 4);
            }
            return records;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Record record;
            record.id = sqlite3_column_int(stmt, 0);
            record.algorithm = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            record.inputFile = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            record.outputFile = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            record.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            if (sqlite3_column_text(stmt, 5)) {
                record.notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            }
            records.push_back(record);
        }

        sqlite3_finalize(stmt);
        return records;
    }

    std::vector<Record> findRecordsByFilename(const std::string& filename) {
        std::vector<Record> records;
        if (!db) return records;

        const char* searchSQL = R"(
            SELECT id, algorithm, input_file, output_file, 
                   datetime(timestamp, 'localtime'), notes
            FROM encryption_records
            WHERE input_file LIKE ? OR output_file LIKE ?
            ORDER BY timestamp DESC;
        )";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, searchSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to prepare search: " + string(sqlite3_errmsg(db)), 4);
            }
            return records;
        }

        std::string searchPattern = "%" + filename + "%";
        sqlite3_bind_text(stmt, 1, searchPattern.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, searchPattern.c_str(), -1, SQLITE_STATIC);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Record record;
            record.id = sqlite3_column_int(stmt, 0);
            record.algorithm = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            record.inputFile = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            record.outputFile = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            record.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            if (sqlite3_column_text(stmt, 5)) {
                record.notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            }
            records.push_back(record);
        }

        sqlite3_finalize(stmt);
        return records;
    }

    bool deleteRecord(int id) {
        if (!db) return false;

        const char* deleteSQL = "DELETE FROM encryption_records WHERE id = ?;";
        sqlite3_stmt* stmt;

        int rc = sqlite3_prepare_v2(db, deleteSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to prepare delete: " + string(sqlite3_errmsg(db)), 4);
            }
            return false;
        }

        sqlite3_bind_int(stmt, 1, id);
        rc = sqlite3_step(stmt);
        bool success = (rc == SQLITE_DONE);

        if (success && ui) {
            ui->printMain("Record deleted successfully", 2);
        }
        else if (ui) {
            ui->printMain("Failed to delete record", 4);
        }

        sqlite3_finalize(stmt);
        return success;
    }

    bool clearDatabase() {
        if (!db) return false;

        const char* clearSQL = "DELETE FROM encryption_records;";
        char* errMsg = nullptr;

        int rc = sqlite3_exec(db, clearSQL, nullptr, nullptr, &errMsg);
        bool success = (rc == SQLITE_OK);

        if (success && ui) {
            ui->printMain("All records cleared from database", 2);
        }
        else if (ui) {
            ui->printMain("Failed to clear database: " + string(errMsg), 4);
            sqlite3_free(errMsg);
        }

        return success;
    }

    int getRecordCount() {
        if (!db) return 0;

        const char* countSQL = "SELECT COUNT(*) FROM encryption_records;";
        sqlite3_stmt* stmt;

        int rc = sqlite3_prepare_v2(db, countSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) return 0;

        int count = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }

        sqlite3_finalize(stmt);
        return count;
    }

    void display() const {
        if (ui) {
            ui->printMain("\n" + string(80, '='), 3);
            ui->printMain(" ENCRYPTION RECORDS DATABASE ", 3);
            ui->printMain(string(80, '='), 3);

            EncryptedDatabase* nonConstThis = const_cast<EncryptedDatabase*>(this);
            auto records = nonConstThis->getAllRecords();

            if (records.empty()) {
                string spaces(40, ' ');
                ui->printMain(spaces + "Database is empty.", 4);
            }
            else {
                ui->printMain(string(6, '-') + string(15, '-') + string(30, '-') +
                    string(30, '-') + string(20, '-') + string(20, '-'), 2);

                ui->printMain("ID    Algorithm      Input File                   Output File                  Timestamp           Notes", 5);

                for (const auto& record : records) {
                    std::string dispInput = record.inputFile;
                    if (dispInput.length() > 28) {
                        dispInput = dispInput.substr(0, 25) + "...";
                    }

                    std::string dispOutput = record.outputFile;
                    if (dispOutput.length() > 28) {
                        dispOutput = dispOutput.substr(0, 25) + "...";
                    }

                    std::string dispNotes = record.notes;
                    if (dispNotes.length() > 18) {
                        dispNotes = dispNotes.substr(0, 15) + "...";
                    }

                    char buffer[256];
                    snprintf(buffer, sizeof(buffer), "%-5d %-13s %-28s %-28s %-19s %-18s",
                        record.id, record.algorithm.c_str(), dispInput.c_str(),
                        dispOutput.c_str(), record.timestamp.c_str(), dispNotes.c_str());

                    ui->printMain(buffer, 2);
                }

                ui->printMain("\n" + string(80, '-'), 2);
                ui->printMain(" Total records: " + to_string(records.size()), 3);
            }

            ui->printMain(string(80, '='), 3);
        }
    }

    void save() {
        // SQLite automatically saves, but we can force a checkpoint if needed
        if (db) {
            sqlite3_wal_checkpoint(db, nullptr);
        }
    }
};
#endif // ENCRYPTED_DATABASE_H