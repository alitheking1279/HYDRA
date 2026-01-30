#ifndef ADVANCED_PORT_SCANNER_H
#define ADVANCED_PORT_SCANNER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "PortScanDatabase.h"

// Forward declaration
class HydraUI;
extern HydraUI* ui;

/**
 * Multi-threaded network port scanner with database integration
 * Supports TCP connect scanning, banner grabbing, service detection
 */
class AdvancedPortScanner {
public:
    struct ScanResult {
        int port;
        string service;
        string state;
        string banner;
        string protocol;
        double response_time;

        ScanResult(int p = 0, string s = "", string st = "CLOSED", string b = "",
            string prot = "TCP", double rt = 0.0)
            : port(p), service(s), state(st), banner(b), protocol(prot), response_time(rt) {
        }
    };

private:
    unordered_map<int, pair<string, string>> commonPorts = {
        {21, {"FTP", "TCP"}},
        {22, {"SSH", "TCP"}},
        {23, {"Telnet", "TCP"}},
        {25, {"SMTP", "TCP"}},
        {53, {"DNS", "UDP/TCP"}},
        {80, {"HTTP", "TCP"}},
        {110, {"POP3", "TCP"}},
        {135, {"RPC", "TCP"}},
        {139, {"NetBIOS", "TCP"}},
        {143, {"IMAP", "TCP"}},
        {443, {"HTTPS", "TCP"}},
        {445, {"SMB", "TCP"}},
        {465, {"SMTPS", "TCP"}},
        {587, {"SMTP", "TCP"}},
        {993, {"IMAPS", "TCP"}},
        {995, {"POP3S", "TCP"}},
        {1433, {"MSSQL", "TCP"}},
        {1521, {"Oracle", "TCP"}},
        {1723, {"PPTP", "TCP"}},
        {3306, {"MySQL", "TCP"}},
        {3389, {"RDP", "TCP"}},
        {5432, {"PostgreSQL", "TCP"}},
        {5900, {"VNC", "TCP"}},
        {6379, {"Redis", "TCP"}},
        {8080, {"HTTP-Proxy", "TCP"}},
        {8443, {"HTTPS-Alt", "TCP"}},
        {8888, {"HTTP-Alt", "TCP"}},
        {9000, {"PHP-FPM", "TCP"}},
        {9200, {"Elasticsearch", "TCP"}},
        {27017, {"MongoDB", "TCP"}}
    };

    template<typename T>
    class ThreadSafeQueue {
    private:
        queue<T> q;
        mutex mtx;
        condition_variable cv;

    public:
        void push(T item) {
            lock_guard<mutex> lock(mtx);
            q.push(item);
            cv.notify_one();
        }

        bool pop(T& item) {
            unique_lock<mutex> lock(mtx);
            if (q.empty()) return false;
            item = q.front();
            q.pop();
            return true;
        }

        size_t size() {
            lock_guard<mutex> lock(mtx);
            return q.size();
        }

        bool empty() {
            lock_guard<mutex> lock(mtx);
            return q.empty();
        }

        void clear() {
            lock_guard<mutex> lock(mtx);
            while (!q.empty()) q.pop();
        }
    };

    ThreadSafeQueue<int> portQueue;
    vector<ScanResult> results;
    mutex resultsMutex;
    atomic<int> openPorts{ 0 };
    atomic<int> scannedPorts{ 0 };
    atomic<int> totalPorts{ 0 };
    atomic<bool> stopScan{ false };

    int timeout = 2000;
    int maxThreads = 100;
    string scanType = "TCP";
    string targetIP;

    PortScanDatabase scanDB;  // Database instance

public:
    AdvancedPortScanner() : scanDB() {}

    bool isValidIP(const string& ip) {
        regex ipPattern("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
        return regex_match(ip, ipPattern);
    }

    string getServiceName(int port) {
        auto it = commonPorts.find(port);
        if (it != commonPorts.end()) {
            return it->second.first;
        }

        if (port == 161 || port == 162) return "SNMP";
        if (port == 389) return "LDAP";
        if (port == 636) return "LDAPS";
        if (port == 1434) return "MSSQL Monitor";
        if (port == 2375 || port == 2376) return "Docker";
        if (port == 2483 || port == 2484) return "Oracle";
        if (port == 3000) return "Node.js";
        if (port == 5000) return "Python Flask";
        if (port == 5601) return "Kibana";
        if (port == 5984) return "CouchDB";
        if (port == 6379) return "Redis";
        if (port == 8000 || port == 8008 || port == 8081) return "HTTP-Alt";
        if (port == 11211) return "Memcached";

        return "Unknown";
    }

    bool tcpConnectScan(const string& ip, int port, ScanResult& result) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            return false;
        }

        DWORD timeoutVal = timeout;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeoutVal, sizeof(timeoutVal));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeoutVal, sizeof(timeoutVal));

        sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        target.sin_addr.s_addr = inet_addr(ip.c_str());

        auto start = chrono::high_resolution_clock::now();

        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        connect(sock, (sockaddr*)&target, sizeof(target));

        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);

        timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        int selectResult = select(0, NULL, &writefds, NULL, &tv);
        bool isOpen = false;

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> elapsed = end - start;
        result.response_time = elapsed.count() * 1000;

        if (selectResult > 0) {
            int error = 0;
            int len = sizeof(error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
            isOpen = (error == 0);

            if (isOpen) {
                string banner = grabBanner(sock, port);
                result.banner = banner;
                result.service = detectServiceByBanner(banner);
            }
        }

        closesocket(sock);
        return isOpen;
    }

    string grabBanner(SOCKET sock, int port) {
        u_long mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);

        DWORD timeoutVal = 3000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeoutVal, sizeof(timeoutVal));

        string banner;
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));

        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            banner = string(buffer);

            banner.erase(remove(banner.begin(), banner.end(), '\r'), banner.end());
            size_t pos = banner.find('\n');
            if (pos != string::npos) {
                banner = banner.substr(0, pos);
            }
            if (banner.length() > 100) {
                banner = banner.substr(0, 97) + "...";
            }
        }
        else {
            string probe;

            if (port == 80 || port == 8080 || port == 8888) {
                probe = "HEAD / HTTP/1.0\r\n\r\n";
            }
            else if (port == 22) {
                probe = "SSH-2.0-Client\r\n";
            }
            else if (port == 25 || port == 587) {
                probe = "EHLO example.com\r\n";
            }

            if (!probe.empty()) {
                send(sock, probe.c_str(), probe.size(), 0);
                memset(buffer, 0, sizeof(buffer));
                bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    banner = string(buffer);

                    banner.erase(remove(banner.begin(), banner.end(), '\r'), banner.end());
                    size_t pos = banner.find('\n');
                    if (pos != string::npos) {
                        banner = banner.substr(0, pos);
                    }
                }
            }
        }

        return banner;
    }

    string detectServiceByBanner(const string& banner) {
        if (banner.empty()) return "Unknown";

        string bannerLower = banner;
        transform(bannerLower.begin(), bannerLower.end(), bannerLower.begin(), ::tolower);

        if (bannerLower.find("http") != string::npos ||
            bannerLower.find("apache") != string::npos ||
            bannerLower.find("nginx") != string::npos ||
            bannerLower.find("iis") != string::npos) {
            return "Web Server";
        }
        if (bannerLower.find("ssh") != string::npos) return "SSH";
        if (bannerLower.find("ftp") != string::npos) return "FTP";
        if (bannerLower.find("smtp") != string::npos) return "SMTP";
        if (bannerLower.find("mysql") != string::npos) return "MySQL";
        if (bannerLower.find("postgres") != string::npos) return "PostgreSQL";
        if (bannerLower.find("redis") != string::npos) return "Redis";
        if (bannerLower.find("microsoft") != string::npos) return "Microsoft";
        if (bannerLower.find("oracle") != string::npos) return "Oracle";
        if (bannerLower.find("docker") != string::npos) return "Docker";

        return "Unknown";
    }

    void scanWorker() {
        int port;
        while (!stopScan && portQueue.pop(port)) {
            scannedPorts++;

            ScanResult result(port);
            result.service = getServiceName(port);
            result.protocol = (scanType == "UDP") ? "UDP" : "TCP";

            bool isOpen = false;

            if (scanType == "TCP") {
                isOpen = tcpConnectScan(targetIP, port, result);
            }

            if (isOpen) {
                openPorts++;
                result.state = "OPEN";

                {
                    lock_guard<mutex> lock(resultsMutex);
                    results.push_back(result);
                }

                displaySingleResult(result);
            }

            if (scannedPorts % 10 == 0) {
                displayProgress();
            }

            this_thread::sleep_for(chrono::milliseconds(10));

            // ESC check
            nodelay(stdscr, TRUE);
            if (getch() == 27) {
                nodelay(stdscr, FALSE);
                stopScan = true;
                return;
            }
            nodelay(stdscr, FALSE);
        }
    }

    void displaySingleResult(const ScanResult& result) {
        lock_guard<mutex> lock(resultsMutex);
        string output = "[+] Port " + to_string(result.port) + " " + result.protocol +
            " - " + result.state + " - " + result.service;

        if (!result.banner.empty()) {
            output += " - " + result.banner;
        }

        if (result.response_time > 0) {
            output += " (" + to_string((int)result.response_time) + "ms)";
        }

        if (ui) {
            ui->printMain(output, 2);
        }
    }

    void displayProgress() {
        int current = scannedPorts.load();
        int total = totalPorts.load();

        if (total > 0 && ui) {
            float percent = (float)current / total * 100;
            string status = "[*] Progress: " + to_string(current) + "/" + to_string(total) +
                " (" + to_string((int)percent) + "%) Open: " + to_string(openPorts.load());
            ui->printStatus(status, 5);
        }
    }

    void displayFinalResults() {
        if (ui) {
            ui->clearMain();
            ui->printMain("=========================================", 3);
            ui->printMain("     SCAN COMPLETE - " + targetIP, 3);
            ui->printMain("=========================================", 3);

            if (results.empty()) {
                ui->printMain("[-] No open ports found.", 4);
                return;
            }

            sort(results.begin(), results.end(),
                [](const ScanResult& a, const ScanResult& b) { return a.port < b.port; });

            ui->printMain("PORT     PROTOCOL  STATE     SERVICE               TIME(ms)  BANNER", 5);
            ui->printMain("--------------------------------------------------------------------", 2);

            for (const auto& result : results) {
                string portStr = to_string(result.port);
                string line = portStr + string(8 - portStr.length(), ' ') +
                    result.protocol + string(10 - result.protocol.length(), ' ') +
                    result.state + string(9 - result.state.length(), ' ') +
                    result.service + string(22 - result.service.length(), ' ') +
                    to_string((int)result.response_time) + "ms";

                if (!result.banner.empty()) {
                    line += "  " + result.banner;
                }

                ui->printMain(line, 2);
            }

            ui->printMain("\nSummary: " + to_string(results.size()) + " open ports found.", 3);
        }
    }

    void saveResultsToFile(const string& filename) {
        ofstream file(filename);
        if (!file.is_open()) {
            if (ui) ui->showMessage("Failed to save results.", 4);
            return;
        }

        time_t now = time(nullptr);
        file << "Port Scan Results" << endl;
        file << "Target: " << targetIP << endl;
        file << "Scan Time: " << ctime(&now);
        file << "Scan Type: " << scanType << endl;
        file << "Threads: " << maxThreads << endl;
        file << "========================================" << endl << endl;

        if (results.empty()) {
            file << "No open ports found." << endl;
        }
        else {
            file << left << setw(8) << "PORT"
                << setw(10) << "PROTOCOL"
                << setw(10) << "STATE"
                << setw(20) << "SERVICE"
                << setw(10) << "TIME(ms)"
                << "BANNER" << endl;
            file << string(80, '-') << endl;

            for (const auto& result : results) {
                file << left << setw(8) << result.port
                    << setw(10) << result.protocol
                    << setw(10) << result.state
                    << setw(20) << result.service
                    << setw(10) << fixed << setprecision(2) << result.response_time
                    << result.banner << endl;
            }

            file << endl << "Total open ports: " << results.size() << endl;
        }

        file.close();
        if (ui) ui->showMessage("Results saved to: " + filename, 2);
    }

    // New method to save scan to database
    bool saveToDatabase(double duration_seconds) {
        int session_id = scanDB.saveScanSession(targetIP, scanType,
            totalPorts, openPorts,
            duration_seconds, maxThreads);

        if (session_id > 0 && !results.empty()) {
            // Convert ScanResult to tuple format for database
            std::vector<std::tuple<int, std::string, std::string, std::string, std::string, double>> dbResults;
            for (const auto& result : results) {
                dbResults.push_back(std::make_tuple(
                    result.port,
                    result.protocol,
                    result.state,
                    result.service,
                    result.banner,
                    result.response_time
                ));
            }
            return scanDB.saveScanResults(session_id, dbResults);
        }
        return session_id > 0;
    }

    // Display scan history from database
    void displayScanHistory() {
        scanDB.displaySessions();
    }

    // Display specific scan session details
    void displaySessionDetails(int session_id) {
        scanDB.displaySessionDetails(session_id);
    }

    vector<ScanResult> scan(const string& ip,
        const vector<int>& ports = {},
        const string& type = "TCP",
        int threads = 50,
        int customTimeout = 2000) {

        results.clear();
        openPorts = 0;
        scannedPorts = 0;
        stopScan = false;
        timeout = customTimeout;
        maxThreads = threads;
        scanType = type;
        targetIP = ip;

        portQueue.clear();

        if (!isValidIP(ip)) {
            if (ui) ui->showMessage("Invalid IP address.", 4);
            return results;
        }

        vector<int> portsToScan;
        if (ports.empty()) {
            vector<int> topPorts = {
                21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
                1723,3306,3389,5900,8080,8443,
                20,26,69,79,81,82,83,84,85,86,87,88,89,90,109,110,119,123,135,137,
                138,139,143,161,162,177,179,194,220,389,443,445,464,465,513,514,
                515,520,521,531,543,544,546,547,548,554,563,587,631,636,646,647,
                648,652,654,655,657,660,666,674,691,692,695,698,699,700,701,702,
                706,711,712,720,749,750,751,752,753,754,760,782,829,830,831,832,
                833,843,847,848,853,860,861,862,873,888,897,898,899,900,901,902,
                903,904,911,912,913,914,915,916,917,918,919,920,921,922,923,924,
                925,926,927,928,929,930,931,932,933,934,935,936,937,938,939,940,
                941,942,943,944,945,946,947,948,949,950,951,952,953,954,955,956,
                957,958,959,960,961,962,963,964,965,966,967,968,969,970,971,972,
                973,974,975,976,977,978,979,980,981,982,983,984,985,986,987,988,
                989,990,991,992,993,994,995,996,997,998,999,1000
            };
            portsToScan = topPorts;
        }
        else {
            portsToScan = ports;
        }

        totalPorts = portsToScan.size();

        for (int port : portsToScan) {
            portQueue.push(port);
        }

        if (ui) {
            ui->clearMain();
            ui->printMain("=========================================", 3);
            ui->printMain("     ADVANCED PORT SCANNER", 3);
            ui->printMain("=========================================", 3);
            ui->printMain("Target: " + targetIP, 2);
            ui->printMain("Ports: " + to_string(totalPorts) + " ports", 2);
            ui->printMain("Threads: " + to_string(maxThreads), 2);
            ui->printMain("Type: " + scanType, 2);
            ui->printMain("", 2);
        }

        vector<thread> workerThreads;
        auto startTime = chrono::high_resolution_clock::now();

        for (int i = 0; i < maxThreads; i++) {
            workerThreads.emplace_back(&AdvancedPortScanner::scanWorker, this);
        }

        for (auto& thread : workerThreads) {
            if (thread.joinable()) {
                thread.join();
            }
        }

        auto endTime = chrono::high_resolution_clock::now();
        chrono::duration<double> elapsed = endTime - startTime;

        displayFinalResults();

        if (ui) {
            ui->printMain("\nScan duration: " + to_string((int)elapsed.count()) + " seconds", 3);
        }

        // Save to database
        if (ui) {
            string saveToDB = ui->getInput("Save scan results to database? (y/n): ");
            if (saveToDB == "y" || saveToDB == "Y") {
                if (saveToDatabase(elapsed.count())) {
                    ui->showMessage("Scan results saved to database", 2);
                }
                else {
                    ui->showMessage("Failed to save to database", 4);
                }
            }
        }

        return results;
    }

    void stop() {
        stopScan = true;
    }

    void quickScan(const string& ip) {
        vector<int> quickPorts = {
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
            443, 445, 993, 995, 1723, 3306, 3389, 5900,
            8080, 8443
        };

        scan(ip, quickPorts, "TCP", 30, 1000);
    }

    void scanRange(const string& baseIP, int start, int end) {
        if (ui) {
            ui->printMain("[*] Scanning IP range: " + baseIP + to_string(start) +
                " - " + baseIP + to_string(end), 5);
        }

        vector<string> liveHosts;

        for (int i = start; i <= end && !stopScan; i++) {
            string ip = baseIP + to_string(i);

            if (ui && i % 10 == 0) {
                ui->showProgress(i - start + 1, end - start + 1, "Testing " + ip);
            }

            SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock != INVALID_SOCKET) {
                sockaddr_in target;
                target.sin_family = AF_INET;
                target.sin_port = htons(80);
                target.sin_addr.s_addr = inet_addr(ip.c_str());

                u_long mode = 1;
                ioctlsocket(sock, FIONBIO, &mode);

                connect(sock, (sockaddr*)&target, sizeof(target));

                fd_set writefds;
                FD_ZERO(&writefds);
                FD_SET(sock, &writefds);

                timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;

                if (select(0, NULL, &writefds, NULL, &tv) > 0) {
                    int error = 0;
                    int len = sizeof(error);
                    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);

                    if (error == 0) {
                        liveHosts.push_back(ip);
                        if (ui) {
                            ui->printMain("[+] Live host: " + ip, 2);
                        }
                    }
                }

                closesocket(sock);
            }

            this_thread::sleep_for(chrono::milliseconds(50));

            // ESC check
            nodelay(stdscr, TRUE);
            if (getch() == 27) {
                nodelay(stdscr, FALSE);
                stopScan = true;
                break;
            }
            nodelay(stdscr, FALSE);
        }

        if (ui) {
            ui->clearMain();
            if (liveHosts.empty()) {
                ui->printMain("[-] No live hosts found in range.", 4);
            }
            else {
                ui->printMain("[+] Found " + to_string(liveHosts.size()) + " live hosts:", 3);
                for (const auto& host : liveHosts) {
                    ui->printMain("    " + host, 2);
                }
            }
        }
    }
};
#endif // ADVANCED_PORT_SCANNER_H