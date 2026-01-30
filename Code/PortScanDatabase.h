#ifndef PORT_SCAN_DATABASE_H
#define PORT_SCAN_DATABASE_H

#include <string>
#include <vector>
#include <tuple>
#include "SQLite/sqlite3.h"

// Forward declaration of UI class
class HydraUI;
extern HydraUI* ui;  // Global UI instance

/**
 * Database manager for storing and retrieving port scan results
 * Uses SQLite for persistent storage of scan sessions and results
 */
class PortScanDatabase {
private:
    sqlite3* db;
    std::string dbPath;

public:
    PortScanDatabase(const std::string& dbFile = "port_scan.db") : db(nullptr), dbPath(dbFile) {
        initializeDatabase();
    }

    ~PortScanDatabase() {
        if (db) {
            sqlite3_close(db);
        }
    }

private:
    void initializeDatabase() {
        int rc = sqlite3_open(dbPath.c_str(), &db);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to open scan database: " + string(sqlite3_errmsg(db)), 4);
            }
            db = nullptr;
            return;
        }

        // Create scan sessions table
        const char* createSessionsSQL = R"(
            CREATE TABLE IF NOT EXISTS scan_sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                total_ports INTEGER NOT NULL,
                open_ports INTEGER NOT NULL,
                scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                duration_seconds REAL,
                threads INTEGER,
                status TEXT DEFAULT 'completed'
            );
        )";

        // Create scan results table
        const char* createResultsSQL = R"(
            CREATE TABLE IF NOT EXISTS scan_results (
                result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service TEXT NOT NULL,
                response_time_ms REAL,
                banner TEXT,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id) ON DELETE CASCADE
            );
            
            CREATE INDEX IF NOT EXISTS idx_session_id ON scan_results(session_id);
            CREATE INDEX IF NOT EXISTS idx_target_ip ON scan_sessions(target_ip);
            CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_sessions(scan_time);
        )";

        char* errMsg = nullptr;
        rc = sqlite3_exec(db, createSessionsSQL, nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK && ui) {
            ui->printMain("Failed to create sessions table: " + string(errMsg), 4);
            sqlite3_free(errMsg);
        }

        errMsg = nullptr;
        rc = sqlite3_exec(db, createResultsSQL, nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK && ui) {
            ui->printMain("Failed to create results table: " + string(errMsg), 4);
            sqlite3_free(errMsg);
        }

        // Enable foreign keys
        sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
    }

public:
    struct ScanSession {
        int session_id;
        std::string target_ip;
        std::string scan_type;
        int total_ports;
        int open_ports;
        std::string scan_time;
        double duration_seconds;
        int threads;
        std::string status;
    };

    struct ScanResultRecord {
        int result_id;
        int session_id;
        int port;
        std::string protocol;
        std::string state;
        std::string service;
        double response_time_ms;
        std::string banner;
    };

    int saveScanSession(const std::string& target_ip, const std::string& scan_type,
        int total_ports, int open_ports, double duration_seconds,
        int threads = 50) {
        if (!db) return -1;

        const char* insertSQL = R"(
            INSERT INTO scan_sessions (target_ip, scan_type, total_ports, 
                                      open_ports, duration_seconds, threads)
            VALUES (?, ?, ?, ?, ?, ?);
        )";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to prepare session statement: " + string(sqlite3_errmsg(db)), 4);
            }
            return -1;
        }

        sqlite3_bind_text(stmt, 1, target_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, scan_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, total_ports);
        sqlite3_bind_int(stmt, 4, open_ports);
        sqlite3_bind_double(stmt, 5, duration_seconds);
        sqlite3_bind_int(stmt, 6, threads);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return -1;
        }

        int session_id = sqlite3_last_insert_rowid(db);
        sqlite3_finalize(stmt);

        return session_id;
    }

    bool saveScanResults(int session_id, const std::vector<std::tuple<int, std::string, std::string, std::string, std::string, double>>& results) {
        if (!db || results.empty()) return false;

        const char* insertSQL = R"(
            INSERT INTO scan_results (session_id, port, protocol, state, 
                                     service, response_time_ms, banner)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        )";

        sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to prepare results statement: " + string(sqlite3_errmsg(db)), 4);
            }
            return false;
        }

        bool success = true;
        for (const auto& result : results) {
            sqlite3_reset(stmt);

            int port = std::get<0>(result);
            std::string protocol = std::get<1>(result);
            std::string state = std::get<2>(result);
            std::string service = std::get<3>(result);
            std::string banner = std::get<4>(result);
            double response_time = std::get<5>(result);

            sqlite3_bind_int(stmt, 1, session_id);
            sqlite3_bind_int(stmt, 2, port);
            sqlite3_bind_text(stmt, 3, protocol.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, state.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 5, service.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_double(stmt, 6, response_time);

            if (!banner.empty()) {
                sqlite3_bind_text(stmt, 7, banner.c_str(), -1, SQLITE_STATIC);
            }
            else {
                sqlite3_bind_null(stmt, 7);
            }

            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                success = false;
                break;
            }
        }

        sqlite3_finalize(stmt);

        if (success) {
            sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
            if (ui) {
                ui->printMain("Saved " + to_string(results.size()) + " scan results to database", 2);
            }
        }
        else {
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            if (ui) {
                ui->printMain("Failed to save scan results to database", 4);
            }
        }

        return success;
    }

    std::vector<ScanSession> getScanSessions() {
        std::vector<ScanSession> sessions;
        if (!db) return sessions;

        const char* selectSQL = R"(
            SELECT session_id, target_ip, scan_type, total_ports, open_ports,
                   datetime(scan_time, 'localtime'), duration_seconds, threads, status
            FROM scan_sessions
            ORDER BY scan_time DESC
            LIMIT 100;
        )";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to prepare sessions query: " + string(sqlite3_errmsg(db)), 4);
            }
            return sessions;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ScanSession session;
            session.session_id = sqlite3_column_int(stmt, 0);
            session.target_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            session.scan_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            session.total_ports = sqlite3_column_int(stmt, 3);
            session.open_ports = sqlite3_column_int(stmt, 4);
            session.scan_time = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            session.duration_seconds = sqlite3_column_double(stmt, 6);
            session.threads = sqlite3_column_int(stmt, 7);
            if (sqlite3_column_text(stmt, 8)) {
                session.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            }
            sessions.push_back(session);
        }

        sqlite3_finalize(stmt);
        return sessions;
    }

    std::vector<ScanResultRecord> getScanResults(int session_id) {
        std::vector<ScanResultRecord> results;
        if (!db) return results;

        const char* selectSQL = R"(
            SELECT result_id, session_id, port, protocol, state, service,
                   response_time_ms, banner
            FROM scan_results
            WHERE session_id = ?
            ORDER BY port;
        )";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to prepare results query: " + string(sqlite3_errmsg(db)), 4);
            }
            return results;
        }

        sqlite3_bind_int(stmt, 1, session_id);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ScanResultRecord result;
            result.result_id = sqlite3_column_int(stmt, 0);
            result.session_id = sqlite3_column_int(stmt, 1);
            result.port = sqlite3_column_int(stmt, 2);
            result.protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            result.state = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            result.service = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            result.response_time_ms = sqlite3_column_double(stmt, 6);
            if (sqlite3_column_text(stmt, 7)) {
                result.banner = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            }
            results.push_back(result);
        }

        sqlite3_finalize(stmt);
        return results;
    }

    bool deleteSession(int session_id) {
        if (!db) return false;

        const char* deleteSQL = "DELETE FROM scan_sessions WHERE session_id = ?;";
        sqlite3_stmt* stmt;

        int rc = sqlite3_prepare_v2(db, deleteSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (ui) {
                ui->printMain("Failed to prepare delete: " + string(sqlite3_errmsg(db)), 4);
            }
            return false;
        }

        sqlite3_bind_int(stmt, 1, session_id);
        rc = sqlite3_step(stmt);
        bool success = (rc == SQLITE_DONE);

        sqlite3_finalize(stmt);
        return success;
    }

    void displaySessions() {
        if (!ui) return;

        auto sessions = getScanSessions();

        ui->printMain("\n" + string(80, '='), 3);
        ui->printMain(" PORT SCAN HISTORY ", 3);
        ui->printMain(string(80, '='), 3);

        if (sessions.empty()) {
            string spaces(40, ' ');
            ui->printMain(spaces + "No scan sessions found.", 4);
        }
        else {
            ui->printMain(string(8, '-') + string(16, '-') + string(12, '-') +
                string(10, '-') + string(10, '-') + string(10, '-') +
                string(20, '-'), 2);

            ui->printMain("ID      Target IP       Scan Type  Ports     Open      Time(s)   Scan Time", 5);

            for (const auto& session : sessions) {
                char buffer[256];
                snprintf(buffer, sizeof(buffer), "%-7d %-15s %-10s %-9d %-9d %-9.1f %-19s",
                    session.session_id, session.target_ip.c_str(),
                    session.scan_type.c_str(), session.total_ports,
                    session.open_ports, session.duration_seconds,
                    session.scan_time.c_str());

                ui->printMain(buffer, 2);
            }

            ui->printMain("\n" + string(80, '-'), 2);
            ui->printMain(" Total sessions: " + to_string(sessions.size()), 3);
        }

        ui->printMain(string(80, '='), 3);
    }

    void displaySessionDetails(int session_id) {
        if (!ui) return;

        // Get session info
        const char* sessionSQL = R"(
            SELECT target_ip, scan_type, total_ports, open_ports,
                   datetime(scan_time, 'localtime'), duration_seconds, threads
            FROM scan_sessions
            WHERE session_id = ?;
        )";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sessionSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            ui->printMain("Failed to get session details", 4);
            return;
        }

        sqlite3_bind_int(stmt, 1, session_id);

        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            ui->printMain("Session not found", 4);
            return;
        }

        string target_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        string scan_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        int total_ports = sqlite3_column_int(stmt, 2);
        int open_ports = sqlite3_column_int(stmt, 3);
        string scan_time = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        double duration = sqlite3_column_double(stmt, 5);
        int threads = sqlite3_column_int(stmt, 6);

        sqlite3_finalize(stmt);

        // Get results
        auto results = getScanResults(session_id);

        ui->printMain("\n" + string(80, '='), 3);
        ui->printMain(" SCAN SESSION #" + to_string(session_id) + " - " + target_ip, 3);
        ui->printMain(string(80, '='), 3);

        ui->printMain("Scan Type: " + scan_type, 2);
        ui->printMain("Time: " + scan_time, 2);
        ui->printMain("Duration: " + to_string(duration) + " seconds", 2);
        ui->printMain("Threads: " + to_string(threads), 2);
        ui->printMain("Ports scanned: " + to_string(total_ports), 2);
        ui->printMain("Open ports found: " + to_string(open_ports), 2);

        if (results.empty()) {
            ui->printMain("\nNo open ports found in this scan.", 4);
        }
        else {
            ui->printMain("\nPORT     PROTOCOL  STATE     SERVICE               TIME(ms)  BANNER", 5);
            ui->printMain("--------------------------------------------------------------------", 2);

            for (const auto& result : results) {
                string portStr = to_string(result.port);
                string line = portStr + string(8 - portStr.length(), ' ') +
                    result.protocol + string(10 - result.protocol.length(), ' ') +
                    result.state + string(9 - result.state.length(), ' ') +
                    result.service + string(22 - result.service.length(), ' ') +
                    to_string((int)result.response_time_ms) + "ms";

                if (!result.banner.empty()) {
                    line += "  " + result.banner;
                }

                ui->printMain(line, 2);
            }
        }

        ui->printMain(string(80, '='), 3);
    }
};
#endif // PORT_SCAN_DATABASE_H