/**
 * organiser-agent.cpp
 * ====================
 * Drop-in C++ replacement for organiser-agent.py.
 * Same REST API, same endpoints, same JSON shapes — server.py talks
 * to it identically.  Zero runtime dependencies once compiled.
 *
 * Idle footprint: ~2 MB RAM, 0% CPU  (vs ~50 MB for Python/Flask)
 *
 * Build (Windows — MSVC, from Developer Command Prompt):
 *   cl /EHsc /O2 /std:c++17 organiser-agent.cpp /Fe:organiser-agent.exe
 *   (needs winsock2 — linked automatically via pragma below)
 *
 * Build (Linux / Mac — for testing):
 *   g++ -std=c++17 -O2 -o organiser-agent organiser-agent.cpp -lpthread
 *
 * Run:
 *   set ORGANISER_SECRET=mysecret   (Windows)
 *   set ORGANISER_PORT=7842
 *   organiser-agent.exe
 *
 * Task Scheduler setup (Windows — run at logon, hidden):
 *   Action:  Start a program
 *   Program: C:\path\to\organiser-agent.exe
 *   Start in: C:\path\to\
 *   [ ] Run only when user is logged on  ← uncheck for hidden start
 *
 * Multi-PC / machine identity:
 *   Set ORGANISER_MACHINE_NAME to match this machine's entry in the
 *   hub's PCS registry (see pc-tunnel@.service), e.g. "desktop" or
 *   "laptop". If unset, falls back to the OS hostname. A separate,
 *   randomly-generated machine_id is persisted next to the config dir
 *   on first run — see machine registry section below for why both
 *   exist.
 */

#ifdef _WIN32
  #define _WIN32_WINNT 0x0601
  #pragma comment(lib, "ws2_32.lib")
  #pragma comment(lib, "shell32.lib")
  #pragma comment(lib, "gdi32.lib")
  #pragma comment(lib, "user32.lib")
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <shellapi.h>
  #include <shlobj.h>
  #define IS_WIN 1
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <dirent.h>
  #include <sys/stat.h>
  #include <sys/wait.h>
  #include <sys/select.h>
  #include <signal.h>
  #include <fcntl.h>
  #define IS_WIN 0
  #define SOCKET int
  #define INVALID_SOCKET -1
  #define closesocket close
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

static int         g_port   = 7842;
static std::string g_secret = "";
static const char* VERSION  = "2.2.0-cpp";
static const int   RUN_COMMAND_TIMEOUT_S = 60;
// Hard ceiling for any single-file read (/preview, /read_file_b64),
// regardless of what a caller's max_bytes asks for. See SECURITY_FINDINGS.md
// finding 4 — this was previously unbounded and pre-allocated before the
// real file size was known, so an absurd max_bytes against a tiny file
// caused std::bad_alloc. 20MB comfortably covers file_transfer's 15MB cap
// plus JSON/base64 overhead while still bounding worst-case memory use.
static const size_t MAX_READ_BYTES = 20 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Tiny JSON builder  (no external deps)
// ---------------------------------------------------------------------------

struct Json {
    std::string s;

    static std::string escape(const std::string& v) {
        std::string r; r.reserve(v.size() + 4);
        for (unsigned char c : v) {
            switch(c) {
                case '"':  r += "\\\""; break;
                case '\\': r += "\\\\"; break;
                case '\n': r += "\\n";  break;
                case '\r': r += "\\r";  break;
                case '\t': r += "\\t";  break;
                default:
                    if (c < 0x20) { char buf[8]; snprintf(buf,sizeof(buf),"\\u%04x",c); r+=buf; }
                    else r += (char)c;
            }
        }
        return r;
    }

    static std::string str(const std::string& v){ return "\"" + escape(v) + "\""; }
    static std::string num(long long v){ return std::to_string(v); }
    static std::string boolean(bool v){ return v ? "true" : "false"; }
    static std::string null_val(){ return "null"; }

    static std::string obj(std::initializer_list<std::pair<std::string,std::string>> fields) {
        std::string r = "{";
        bool first = true;
        for (auto& [k,v] : fields) {
            if (!first) r += ",";
            r += str(k) + ":" + v;
            first = false;
        }
        return r + "}";
    }

    static std::string arr(const std::vector<std::string>& items) {
        std::string r = "[";
        for (size_t i=0;i<items.size();i++) {
            if (i) r += ",";
            r += items[i];
        }
        return r + "]";
    }
};

// ---------------------------------------------------------------------------
// Human-readable sizes
// ---------------------------------------------------------------------------

static std::string human(uintmax_t bytes) {
    const char* units[] = {"B","KB","MB","GB","TB"};
    double v = (double)bytes;
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    char buf[32];
    snprintf(buf, sizeof(buf), "%.1f %s", v, units[i]);
    return buf;
}

// ---------------------------------------------------------------------------
// Platform helpers
// ---------------------------------------------------------------------------

static std::string platform_name() {
#if IS_WIN
    return "Windows";
#elif defined(__APPLE__)
    return "macOS";
#else
    return "Linux";
#endif
}

static std::string iso_time(const fs::file_time_type& ft) {
    auto sc = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ft - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
    std::time_t t = std::chrono::system_clock::to_time_t(sc);
    char buf[32]; struct tm tm_s;
#if IS_WIN
    gmtime_s(&tm_s, &t);
#else
    gmtime_r(&t, &tm_s);
#endif
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_s);
    return buf;
}

// Delete-to-trash (Windows: SHFileOperation; others: just unlink)
static bool trash_path(const fs::path& p, std::string& err) {
#if IS_WIN
    std::wstring wstr = p.wstring() + L'\0' + L'\0';
    SHFILEOPSTRUCTW op = {};
    op.wFunc  = FO_DELETE;
    op.pFrom  = wstr.data();
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT;
    int r = SHFileOperationW(&op);
    if (r != 0) { err = "SHFileOperation failed: " + std::to_string(r); return false; }
    return true;
#else
    // macOS / Linux — move to ~/.Trash (best-effort)
    const char* home = getenv("HOME");
    if (home) {
        fs::path trash = fs::path(home) / ".Trash";
        try {
            fs::create_directories(trash);
            fs::path dest = trash / p.filename();
            try {
                fs::rename(p, dest);
                return true;
            } catch (...) {
                // rename() fails across filesystems (EXDEV, e.g. an external
                // drive or a different mount). Fall back to copy-then-remove
                // so the file still ends up in Trash instead of silently
                // becoming an unrecoverable permanent delete.
                fs::copy(p, dest, fs::copy_options::recursive | fs::copy_options::overwrite_existing);
                fs::remove_all(p);
                return true;
            }
        } catch (std::exception& e) {
            err = e.what();
            return false;
        }
    }
    err = "HOME not set; cannot locate Trash";
    return false;
#endif
}

// ---------------------------------------------------------------------------
// run_command — WITH a real, enforced timeout.
//
// The previous implementation used popen()/_popen(), which blocks the
// calling thread until the child exits with no way to interrupt it — a
// runaway or hung command (or one that intentionally ignores stdin/stdout
// closing) would tie up that connection thread forever. This version
// spawns the child directly (fork/exec on POSIX, CreateProcess on
// Windows) so the parent can poll for completion, enforce a deadline, and
// forcibly kill the child (and its process tree) if the deadline passes.
// ---------------------------------------------------------------------------

#if IS_WIN
static std::string run_command(const std::string& cmd, const std::string& cwd,
                                int& retcode, bool& timed_out, size_t cap = 8192,
                                int timeout_s = RUN_COMMAND_TIMEOUT_S) {
    timed_out = false;
    std::string full_cmd = "cmd /c " + cmd;

    SECURITY_ATTRIBUTES sa = {}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        retcode = -1; return "Failed to create pipe";
    }
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi = {};

    // Job object so killing the child also kills anything it spawned
    // (e.g. `cmd /c foo.bat` that launches its own children).
    HANDLE hJob = CreateJobObjectA(nullptr, nullptr);
    if (hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    }

    std::vector<char> cmdline(full_cmd.begin(), full_cmd.end());
    cmdline.push_back('\0');

    BOOL ok = CreateProcessA(
        nullptr, cmdline.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);

    CloseHandle(hWritePipe);
    if (!ok) {
        CloseHandle(hReadPipe);
        if (hJob) CloseHandle(hJob);
        retcode = -1;
        return "CreateProcess failed: " + std::to_string(GetLastError());
    }
    if (hJob) AssignProcessToJobObject(hJob, pi.hProcess);
    ResumeThread(pi.hThread);

    std::string out;
    DWORD waited = WaitForSingleObject(pi.hProcess, (DWORD)timeout_s * 1000);
    if (waited == WAIT_TIMEOUT) {
        timed_out = true;
        if (hJob) TerminateJobObject(hJob, 1);
        else TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 2000);
    }

    // Drain whatever the child wrote (bounded read; no PeekNamedPipe loop
    // needed since the process has already exited or been killed by now).
    char buf[4096]; DWORD nread = 0;
    while (out.size() < cap && ReadFile(hReadPipe, buf, sizeof(buf), &nread, nullptr) && nread > 0) {
        out.append(buf, nread);
    }

    DWORD exitCode = (DWORD)-1;
    if (!timed_out) GetExitCodeProcess(pi.hProcess, &exitCode);
    retcode = timed_out ? -1 : (int)exitCode;

    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (hJob) CloseHandle(hJob);

    if (out.size() > cap) out = out.substr(out.size() - cap);
    return out;
}
#else
static std::string run_command(const std::string& cmd, const std::string& cwd,
                                int& retcode, bool& timed_out, size_t cap = 8192,
                                int timeout_s = RUN_COMMAND_TIMEOUT_S) {
    timed_out = false;
    int pipefd[2];
    if (pipe(pipefd) != 0) { retcode = -1; return "Failed to create pipe"; }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        retcode = -1; return "fork() failed";
    }
    if (pid == 0) {
        // Child: own process group so a timeout kill takes any
        // grandchildren (e.g. `sh -c "sleep 100 & wait"`) with it.
        setpgid(0, 0);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        if (!cwd.empty()) {
            if (chdir(cwd.c_str()) != 0) _exit(127);
        }
        execl("/bin/bash", "bash", "-c", cmd.c_str(), (char*)nullptr);
        _exit(127); // exec failed
    }

    // Parent
    close(pipefd[1]);
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    std::string out;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    int status = 0;
    bool exited = false;

    while (true) {
        fd_set fds; FD_ZERO(&fds); FD_SET(pipefd[0], &fds);
        struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 200000; // 200ms poll
        int sel = select(pipefd[0] + 1, &fds, nullptr, nullptr, &tv);
        if (sel > 0 && FD_ISSET(pipefd[0], &fds)) {
            char buf[4096];
            ssize_t n = read(pipefd[0], buf, sizeof(buf));
            if (n > 0 && out.size() < cap) out.append(buf, n);
        }

        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) { exited = true; break; }

        if (std::chrono::steady_clock::now() >= deadline) {
            timed_out = true;
            kill(-pid, SIGKILL);   // whole process group
            kill(pid, SIGKILL);    // belt-and-braces if setpgid raced
            waitpid(pid, &status, 0);
            break;
        }
    }

    // Drain any remaining buffered output after exit/kill.
    if (exited || timed_out) {
        char buf[4096]; ssize_t n;
        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
            if (out.size() < cap) out.append(buf, n);
        }
    }
    close(pipefd[0]);

    if (timed_out) {
        retcode = -1;
    } else if (WIFEXITED(status)) {
        retcode = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        retcode = -WTERMSIG(status);
    } else {
        retcode = -1;
    }

    if (out.size() > cap) out = out.substr(out.size() - cap);
    return out;
}
#endif

// MD5 (simple implementation — good enough for duplicate detection)
static std::string md5_file(const fs::path& p) {
    // We use a simple FNV-64 as a stand-in for duplicate detection
    // Replace with real MD5 if strict hash compatibility needed
    std::ifstream f(p, std::ios::binary);
    if (!f) return "";
    uint64_t h = 14695981039346656037ULL;
    char buf[4096];
    while (f.read(buf, sizeof(buf)) || f.gcount()) {
        for (std::streamsize i=0; i<f.gcount(); i++) {
            h ^= (uint8_t)buf[i];
            h *= 1099511628211ULL;
        }
    }
    char out[17]; snprintf(out,sizeof(out),"%016llx",(unsigned long long)h);
    return out;
}

// Base64 decode (returns false on malformed input rather than guessing)
static bool b64_decode(const std::string& in, std::vector<uint8_t>& out) {
    auto val = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::string clean;
    clean.reserve(in.size());
    for (unsigned char c : in) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        if (val(c) < 0) return false; // malformed — reject rather than skip silently
        clean += c;
    }
    out.clear();
    out.reserve(clean.size() / 4 * 3 + 3);
    int buf = 0, bits = 0;
    for (unsigned char c : clean) {
        buf = (buf << 6) | val(c);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((buf >> bits) & 0xFF));
        }
    }
    return true;
}

// Base64 encode
static std::string b64_encode(const std::vector<uint8_t>& in) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; out.reserve(((in.size()+2)/3)*4);
    for (size_t i=0;i<in.size();i+=3) {
        uint32_t v = (uint32_t)in[i]<<16;
        if (i+1<in.size()) v|=(uint32_t)in[i+1]<<8;
        if (i+2<in.size()) v|=(uint32_t)in[i+2];
        out+=t[(v>>18)&63]; out+=t[(v>>12)&63];
        out+=(i+1<in.size())?t[(v>>6)&63]:'=';
        out+=(i+2<in.size())?t[v&63]:'=';
    }
    return out;
}

// Screenshot — Windows only via GDI
#if IS_WIN
static std::vector<uint8_t> screenshot_png(int& w_out, int& h_out) {
    // Grab screen via GDI, encode to BMP in memory
    HDC hdc    = GetDC(nullptr);
    int w      = GetSystemMetrics(SM_CXSCREEN);
    int h      = GetSystemMetrics(SM_CYSCREEN);
    HDC hdcMem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
    SelectObject(hdcMem, bmp);
    BitBlt(hdcMem, 0, 0, w, h, hdc, 0, 0, SRCCOPY);

    // Write DIB to memory as BMP
    BITMAPINFOHEADER bi = {};
    bi.biSize = sizeof(bi); bi.biWidth = w; bi.biHeight = -h;
    bi.biPlanes = 1; bi.biBitCount = 24; bi.biCompression = BI_RGB;
    int rowSize = ((w * 3 + 3) & ~3);
    int imgSize = rowSize * h;

    std::vector<uint8_t> pixels(imgSize);
    GetDIBits(hdcMem, bmp, 0, h, pixels.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    // BMP file header + info header + pixels
    BITMAPFILEHEADER bfh = {};
    bfh.bfType    = 0x4D42;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bfh.bfSize    = bfh.bfOffBits + imgSize;

    std::vector<uint8_t> bmp_data;
    bmp_data.resize(bfh.bfSize);
    memcpy(bmp_data.data(), &bfh, sizeof(bfh));
    memcpy(bmp_data.data()+sizeof(bfh), &bi, sizeof(bi));
    memcpy(bmp_data.data()+bfh.bfOffBits, pixels.data(), imgSize);

    DeleteObject(bmp); DeleteDC(hdcMem); ReleaseDC(nullptr, hdc);
    w_out = w; h_out = h;
    return bmp_data;  // BMP bytes — base64 this directly (client can handle BMP)
}
#endif

// ---------------------------------------------------------------------------
// HTTP mini-server
// ---------------------------------------------------------------------------

struct Request {
    std::string method;
    std::string path;
    std::map<std::string,std::string> headers;
    std::map<std::string,std::string> query;
    std::string body;
};

struct Response {
    int status = 200;
    std::string content_type = "application/json";
    std::string body;

    static Response json(int code, const std::string& j) {
        Response r; r.status=code; r.body=j; return r;
    }
    static Response ok(const std::string& j)  { return json(200,j); }
    static Response err(int c, const std::string& msg) {
        return json(c, Json::obj({{"error", Json::str(msg)}}));
    }
};

// Parse query string
static std::map<std::string,std::string> parse_qs(const std::string& qs) {
    std::map<std::string,std::string> m;
    std::istringstream ss(qs);
    std::string tok;
    while (std::getline(ss, tok, '&')) {
        auto eq = tok.find('=');
        if (eq != std::string::npos)
            m[tok.substr(0,eq)] = tok.substr(eq+1);
    }
    return m;
}

// Tiny JSON value extractor (handles "key": "value" and "key": true/false/number)
static std::string json_str(const std::string& body, const std::string& key, const std::string& def="") {
    std::string pat = "\"" + key + "\"";
    auto pos = body.find(pat);
    if (pos == std::string::npos) return def;
    pos = body.find(':', pos+pat.size());
    if (pos == std::string::npos) return def;
    pos = body.find_first_not_of(" \t\r\n", pos+1);
    if (pos == std::string::npos) return def;
    if (body[pos] == '"') {
        auto end = pos + 1;
        std::string v;
        while (end < body.size() && body[end] != '"') {
            if (body[end] == '\\' && end + 1 < body.size()) {
                char esc = body[end + 1];
                switch (esc) {
                    case 'n':  v += '\n'; end += 2; break;
                    case 't':  v += '\t'; end += 2; break;
                    case 'r':  v += '\r'; end += 2; break;
                    case 'b':  v += '\b'; end += 2; break;
                    case 'f':  v += '\f'; end += 2; break;
                    case '"':  v += '"';  end += 2; break;
                    case '\\': v += '\\'; end += 2; break;
                    case '/':  v += '/';  end += 2; break;
                    case 'u': {
                        bool ok = (end + 6 <= body.size());
                        unsigned int cp = 0;
                        for (int k = 0; ok && k < 4; k++) {
                            char c = body[end + 2 + k];
                            cp <<= 4;
                            if (c >= '0' && c <= '9') cp |= (unsigned)(c - '0');
                            else if (c >= 'a' && c <= 'f') cp |= (unsigned)(c - 'a' + 10);
                            else if (c >= 'A' && c <= 'F') cp |= (unsigned)(c - 'A' + 10);
                            else ok = false;
                        }
                        if (ok) {
                            // Encode as UTF-8 (BMP only; no surrogate pair handling)
                            if (cp < 0x80) {
                                v += (char)cp;
                            } else if (cp < 0x800) {
                                v += (char)(0xC0 | (cp >> 6));
                                v += (char)(0x80 | (cp & 0x3F));
                            } else {
                                v += (char)(0xE0 | (cp >> 12));
                                v += (char)(0x80 | ((cp >> 6) & 0x3F));
                                v += (char)(0x80 | (cp & 0x3F));
                            }
                            end += 6;
                        } else {
                            v += 'u'; end += 2; // malformed \u escape, best-effort
                        }
                        break;
                    }
                    default: v += esc; end += 2; break;
                }
                continue;
            }
            v += body[end++];
        }
        return v;
    }
    // number or bool
    auto end2 = body.find_first_of(",}\r\n", pos);
    std::string raw = body.substr(pos, end2-pos);
    // trim
    while (!raw.empty() && raw.back()==' ') raw.pop_back();
    return raw;
}

static bool json_bool(const std::string& body, const std::string& key, bool def=false) {
    std::string v = json_str(body, key, def?"true":"false");
    return v == "true" || v == "1";
}

// Route table
using Handler = std::function<Response(const Request&)>;
static std::map<std::string, Handler> g_routes; // "METHOD /path"

static void add_route(const std::string& method, const std::string& path, Handler h) {
    g_routes[method + " " + path] = std::move(h);
}

// ---------------------------------------------------------------------------
// Machine registry
// ---------------------------------------------------------------------------
// Mirrors organiser-agent.py's scheme (kept in sync deliberately, see
// coordination/status/pc-agent.md):
//   machine_name — human label matching the hub's PCS key (e.g.
//                  "desktop"), from ORGANISER_MACHINE_NAME or else the
//                  OS hostname.
//   machine_id   — random id, generated once, persisted to a small
//                  config file, survives renames/restarts. Distinguishes
//                  "same agent, renamed" from "different agent, same
//                  name reused".

static fs::path config_dir() {
    fs::path base;
#if IS_WIN
    const char* appdata = getenv("APPDATA");
    base = appdata ? fs::path(appdata) : fs::path(getenv("USERPROFILE") ? getenv("USERPROFILE") : ".") / "AppData" / "Roaming";
#else
    const char* xdg = getenv("XDG_CONFIG_HOME");
    base = xdg ? fs::path(xdg) : fs::path(getenv("HOME") ? getenv("HOME") : ".") / ".config";
#endif
    fs::path d = base / "organiser-agent";
    std::error_code ec;
    fs::create_directories(d, ec);
    return d;
}

static std::string gen_uuid_v4() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dis(0, 15);
    const char* hex = "0123456789abcdef";
    std::string s = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    for (auto& c : s) {
        if (c == 'x') c = hex[dis(gen)];
        else if (c == 'y') c = hex[(dis(gen) & 0x3) | 0x8]; // RFC4122 variant bits
    }
    return s;
}

// Deliberately not full JSON parsing here (same tiny json_str helper the
// rest of the file uses) — this file is one record, not general config.
static std::string load_or_create_machine_id(const fs::path& config_path) {
    if (fs::exists(config_path)) {
        std::ifstream f(config_path, std::ios::binary);
        std::stringstream ss; ss << f.rdbuf();
        std::string existing = json_str(ss.str(), "machine_id", "");
        if (!existing.empty()) return existing;
        // fall through — corrupt/empty file, regenerate rather than crash
    }
    std::string id = gen_uuid_v4();
    std::ofstream out(config_path, std::ios::binary | std::ios::trunc);
    if (out) out << Json::obj({{"machine_id", Json::str(id)}});
    return id;
}

static std::string get_hostname() {
#if IS_WIN
    char buf[256]; DWORD sz = sizeof(buf);
    if (GetComputerNameA(buf, &sz)) return std::string(buf, sz);
    return "unknown-windows-host";
#else
    char buf[256];
    if (gethostname(buf, sizeof(buf)) == 0) return std::string(buf);
    return "unknown-host";
#endif
}

static fs::path g_machine_config_path;
static std::string g_machine_id;
static std::string g_machine_name;
static std::string g_config_saved_name;   // last value saved via /config (persisted)
static std::string g_config_saved_secret; // last value saved via /config (persisted)

// Deliberately reads the same three fields with the same tiny json_str
// helper used everywhere else in this file — this is one small record,
// not a case for a general JSON parser.
static void load_config_extras() {
    if (!fs::exists(g_machine_config_path)) return;
    std::ifstream f(g_machine_config_path, std::ios::binary);
    std::stringstream ss; ss << f.rdbuf();
    std::string content = ss.str();
    g_config_saved_name   = json_str(content, "machine_name", "");
    g_config_saved_secret = json_str(content, "secret", "");
}

static void save_config_extras() {
    // Preserve machine_id (already in the file) while updating the other
    // two fields — this is a full rewrite of one small record, matching
    // the file's actual size (a few short fields), not a partial patch.
    std::ofstream out(g_machine_config_path, std::ios::binary | std::ios::trunc);
    if (out) {
        out << Json::obj({
            {"machine_id",   Json::str(g_machine_id)},
            {"machine_name", Json::str(g_config_saved_name)},
            {"secret",       Json::str(g_config_saved_secret)},
        });
    }
}

static void init_machine_registry() {
    g_machine_config_path = config_dir() / "machine.json";
    g_machine_id = load_or_create_machine_id(g_machine_config_path);
    load_config_extras();

    // Precedence: env var (set at service-install time) > config file
    // (set later via /admin) > OS hostname / empty secret.
    const char* name_env = getenv("ORGANISER_MACHINE_NAME");
    g_machine_name = (name_env && *name_env) ? std::string(name_env)
                    : (!g_config_saved_name.empty() ? g_config_saved_name : get_hostname());

    const char* secret_env = getenv("ORGANISER_SECRET");
    if (!(secret_env && *secret_env) && !g_config_saved_secret.empty()) {
        g_secret = g_config_saved_secret;
    }
}

// ---------------------------------------------------------------------------
// Protected paths
// ---------------------------------------------------------------------------
// The Windows system directory (C:\Windows — System32, SysWOW64, WinSxS,
// drivers, etc. all live under it) is off-limits to every file-operation
// endpoint below, so this agent can have free rein over the rest of the
// disk without being able to touch the OS itself.
//
// NOTE: this does NOT cover /run_command. That endpoint runs an arbitrary
// shell command, and there's no reliable way to parse arbitrary cmd/
// PowerShell text to tell whether it touches a protected path — so a
// command run through /run_command can still reach C:\Windows. If you want
// that closed off too, it needs handling at the OS/account-permission
// level (e.g. running the agent as a user without write access to
// C:\Windows), not a string check here.
#if IS_WIN
static fs::path windows_dir() {
    char buf[MAX_PATH] = {0};
    UINT n = GetWindowsDirectoryA(buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) return fs::path(buf);
    const char* sysroot = getenv("SystemRoot");
    return fs::path(sysroot ? sysroot : "C:\\Windows");
}
#endif

static bool is_protected_path(const fs::path& raw) {
#if IS_WIN
    std::error_code ec;
    fs::path resolved = fs::weakly_canonical(raw, ec);
    if (ec) resolved = fs::absolute(raw); // best-effort if it doesn't exist yet

    auto lower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    };
    std::string r = lower(resolved.string());
    std::string w = lower(windows_dir().string());
    if (r.size() < w.size() || r.compare(0, w.size(), w) != 0) return false;
    // boundary check so "C:\Windows2\..." doesn't false-match "C:\Windows"
    return r.size() == w.size() || r[w.size()] == '\\' || r[w.size()] == '/';
#else
    (void)raw;
    return false; // this guard only applies to the Windows deployment target
#endif
}

// Returns true (and fills `out`) if the path is protected — caller should
// `return` immediately with `out` in that case.
static bool reject_if_protected(const fs::path& p, Response& out) {
    if (is_protected_path(p)) {
        out = Response::err(403, "Path is inside the protected Windows system directory: " + p.string());
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

static Response h_status(const Request&) {
    return Response::ok(Json::obj({
        {"version",         Json::str(VERSION)},
        {"platform",        Json::str(platform_name())},
        {"trash_available", Json::boolean(true)},
        {"watched_folders", "[]"},
        {"machine_id",      Json::str(g_machine_id)},
        {"machine_name",    Json::str(g_machine_name)},
    }));
}

static Response h_list(const Request& req) {
    auto folder_s = req.query.count("folder") ? req.query.at("folder") : "";
    bool recursive = req.query.count("recursive") && req.query.at("recursive") == "true";
    if (folder_s.empty()) return Response::err(400, "Missing 'folder' parameter");

    fs::path folder(folder_s);
    Response blocked;
    if (reject_if_protected(folder, blocked)) return blocked;
    if (!fs::exists(folder)) return Response::err(404, "Path does not exist: " + folder_s);
    if (!fs::is_directory(folder)) return Response::err(400, "Not a directory: " + folder_s);

    std::vector<std::string> entries;
    auto process = [&](const fs::path& child) {
        if (child.filename().string().empty() || child.filename().string()[0]=='.') return;
        try {
            fs::file_status st = fs::status(child);
            uintmax_t sz = fs::is_regular_file(st) ? fs::file_size(child) : 0;
            std::string modtime;
            try { modtime = iso_time(fs::last_write_time(child)); } catch(...) {}
            entries.push_back(Json::obj({
                {"name",      Json::str(child.filename().string())},
                {"path",      Json::str(child.string())},
                {"is_dir",    Json::boolean(fs::is_directory(st))},
                {"size_bytes",Json::num((long long)sz)},
                {"modified",  Json::str(modtime)},
                {"extension", Json::str(fs::is_regular_file(st) ? child.extension().string() : "")},
            }));
        } catch(...) {}
    };

    try {
        if (recursive) {
            for (auto& e : fs::recursive_directory_iterator(folder, fs::directory_options::skip_permission_denied))
                process(e.path());
        } else {
            std::vector<fs::path> sorted;
            for (auto& e : fs::directory_iterator(folder)) sorted.push_back(e.path());
            std::sort(sorted.begin(), sorted.end());
            for (auto& p : sorted) process(p);
        }
    } catch(std::exception& e) { return Response::err(500, e.what()); }

    std::string result = "{\"folder\":" + Json::str(folder_s) + ",\"entries\":" + Json::arr(entries) + "}";
    return Response::ok(result);
}

static Response h_move(const Request& req) {
    std::string src_s = json_str(req.body, "source");
    std::string dst_s = json_str(req.body, "destination");
    if (src_s.empty() || dst_s.empty()) return Response::err(400, "Missing source or destination");
    fs::path src(src_s), dst(dst_s);
    Response blocked;
    if (reject_if_protected(src, blocked)) return blocked;
    if (reject_if_protected(dst, blocked)) return blocked;
    if (!fs::exists(src)) return Response::err(404, "Source does not exist: " + src_s);
    try {
        fs::create_directories(dst.parent_path());
        try {
            fs::rename(src, dst);
        } catch (...) {
            // rename() fails across filesystems/drives (EXDEV). Fall back to
            // copy-then-remove so cross-drive moves still work instead of
            // just erroring out.
            fs::copy(src, dst, fs::copy_options::recursive | fs::copy_options::overwrite_existing);
            fs::remove_all(src);
        }
    } catch(std::exception& e) { return Response::err(500, e.what()); }
    return Response::ok(Json::obj({{"message", Json::str("Moved '" + src_s + "' \u2192 '" + dst_s + "'")}}));
}

static Response h_delete(const Request& req) {
    std::string path_s = json_str(req.body, "path");
    bool permanent = json_bool(req.body, "permanent", false);
    if (path_s.empty()) return Response::err(400, "Missing 'path'");
    fs::path p(path_s);
    Response blocked;
    if (reject_if_protected(p, blocked)) return blocked;
    if (!fs::exists(p)) return Response::err(404, "Path does not exist: " + path_s);
    if (permanent) {
        try { fs::remove_all(p); }
        catch(std::exception& e) { return Response::err(500, e.what()); }
        return Response::ok(Json::obj({{"message", Json::str("Permanently deleted '" + path_s + "'")}}));
    } else {
        std::string err;
        if (!trash_path(p, err)) return Response::err(500, err.empty() ? "Trash failed" : err);
        return Response::ok(Json::obj({{"message", Json::str("Sent '" + path_s + "' to Recycle Bin / Trash")}}));
    }
}

static Response h_preview(const Request& req) {
    std::string path_s = req.query.count("path") ? req.query.at("path") : "";
    size_t requested = req.query.count("max_bytes") ? (size_t)std::stoull(req.query.at("max_bytes")) : 4096;
    if (path_s.empty()) return Response::err(400, "Missing 'path'");
    fs::path p(path_s);
    Response blocked;
    if (reject_if_protected(p, blocked)) return blocked;
    if (!fs::exists(p)) return Response::err(404, "Path does not exist: " + path_s);
    if (!fs::is_regular_file(p)) return Response::err(400, "Not a file");

    // Finding 4 (SECURITY_FINDINGS.md): max_bytes was previously
    // attacker-controlled with no upper bound and used to pre-allocate a
    // buffer BEFORE checking the real file size — a request for e.g. 10GB
    // against a 1KB file caused std::bad_alloc. Fix: clamp to a hard
    // ceiling regardless of what's requested, AND never allocate more
    // than the file actually contains.
    std::error_code ec;
    uintmax_t file_size = fs::file_size(p, ec);
    size_t max_bytes = std::min(requested, MAX_READ_BYTES);
    if (!ec) max_bytes = std::min(max_bytes, (size_t)file_size);

    std::ifstream f(p, std::ios::binary);
    if (!f) return Response::err(500, "Cannot open file");
    std::string content(max_bytes, '\0');
    f.read(&content[0], max_bytes);
    content.resize((size_t)f.gcount());
    return Response::ok(Json::obj({{"path", Json::str(path_s)}, {"content", Json::str(content)}}));
}

static Response h_disk_usage(const Request& req) {
    std::string folder_s = req.query.count("folder") ? req.query.at("folder") : "";
    if (folder_s.empty()) return Response::err(400, "Missing 'folder'");
    fs::path folder(folder_s);
    Response blocked;
    if (reject_if_protected(folder, blocked)) return blocked;
    if (!fs::exists(folder)) return Response::err(404, "Path does not exist: " + folder_s);

    std::vector<std::pair<uintmax_t,std::string>> items;
    uintmax_t total = 0;
    try {
        for (auto& e : fs::directory_iterator(folder, fs::directory_options::skip_permission_denied)) {
            if (e.path().filename().string()[0]=='.') continue;
            uintmax_t sz = 0;
            try {
                if (fs::is_directory(e)) {
                    for (auto& f2 : fs::recursive_directory_iterator(e, fs::directory_options::skip_permission_denied))
                        if (fs::is_regular_file(f2)) sz += fs::file_size(f2);
                } else sz = fs::file_size(e);
            } catch(...) {}
            items.push_back({sz, e.path().string()});
            total += sz;
        }
    } catch(std::exception& ex) { return Response::err(500, ex.what()); }

    std::sort(items.begin(), items.end(), [](auto& a, auto& b){ return a.first > b.first; });
    std::vector<std::string> arr;
    for (auto& [sz,path] : items) {
        arr.push_back(Json::obj({
            {"path",       Json::str(path)},
            {"size_bytes", Json::num((long long)sz)},
            {"size_human", Json::str(human(sz))},
        }));
    }
    std::string result = "{\"folder\":" + Json::str(folder_s)
        + ",\"items\":" + Json::arr(arr)
        + ",\"total_bytes\":" + Json::num((long long)total)
        + ",\"total_human\":" + Json::str(human(total)) + "}";
    return Response::ok(result);
}

static Response h_run_command(const Request& req) {
    std::string cmd = json_str(req.body, "command");
    std::string cwd = json_str(req.body, "working_dir");
    if (cmd.empty()) return Response::err(400, "No command provided");
    if (!cwd.empty()) {
        std::error_code ec;
        if (!fs::is_directory(cwd, ec)) {
            return Response::err(400, "working_dir does not exist or is not a directory: " + cwd);
        }
    }
    int rc = 0;
    bool timed_out = false;
    std::string out = run_command(cmd, cwd, rc, timed_out);
    if (timed_out) {
        return Response::json(408, Json::obj({
            {"error", Json::str("Command timed out after " + std::to_string(RUN_COMMAND_TIMEOUT_S) + "s")},
            {"stdout", Json::str(out)},
        }));
    }
    return Response::ok(Json::obj({
        {"returncode", Json::num(rc)},
        {"stdout",     Json::str(out)},
        {"stderr",     Json::str("")},
    }));
}

static Response h_duplicates(const Request& req) {
    std::string folder_s = req.query.count("folder") ? req.query.at("folder") : "";
    if (folder_s.empty()) return Response::err(400, "Missing 'folder'");
    fs::path folder(folder_s);
    Response blocked;
    if (reject_if_protected(folder, blocked)) return blocked;
    if (!fs::exists(folder)) return Response::err(404, "Path does not exist: " + folder_s);

    std::map<std::string, std::vector<fs::path>> hash_map;
    try {
        for (auto& e : fs::recursive_directory_iterator(folder, fs::directory_options::skip_permission_denied)) {
            if (!fs::is_regular_file(e)) continue;
            std::string h = md5_file(e.path());
            if (!h.empty()) hash_map[h].push_back(e.path());
        }
    } catch(...) {}

    std::vector<std::string> groups;
    for (auto& [hash, files] : hash_map) {
        if (files.size() < 2) continue;
        uintmax_t sz = 0;
        try { sz = fs::file_size(files[0]); } catch(...) {}
        uintmax_t wasted = sz * (files.size()-1);
        std::vector<std::string> fpaths;
        for (auto& f : files) fpaths.push_back(Json::str(f.string()));
        groups.push_back(Json::obj({
            {"hash",        Json::str(hash)},
            {"count",       Json::num((long long)files.size())},
            {"size_bytes",  Json::num((long long)sz)},
            {"size_human",  Json::str(human(sz))},
            {"wasted_bytes",Json::num((long long)wasted)},
            {"wasted_human",Json::str(human(wasted))},
            {"files",       Json::arr(fpaths)},
        }));
    }
    std::string result = "{\"folder\":" + Json::str(folder_s) + ",\"groups\":" + Json::arr(groups) + "}";
    return Response::ok(result);
}

static Response h_screenshot(const Request& req) {
#if IS_WIN
    std::string save_path = json_str(req.body, "save_path");
    if (!save_path.empty()) {
        Response blocked;
        if (reject_if_protected(fs::path(save_path), blocked)) return blocked;
    }
    int w=0, h=0;
    std::vector<uint8_t> data;
    try {
        data = screenshot_png(w, h);
    } catch (std::exception& e) {
        return Response::err(500, std::string("Screenshot capture failed: ") + e.what());
    }
    if (data.empty()) return Response::err(500, "Screenshot capture failed: no data captured");
    std::string b64 = b64_encode(data);
    if (!save_path.empty()) {
        std::ofstream f(save_path, std::ios::binary);
        if (!f) return Response::err(500, "Screenshot captured but failed to open save_path for writing: " + save_path);
        f.write((char*)data.data(), data.size());
        if (!f) return Response::err(500, "Screenshot captured but failed to write save_path: " + save_path);
    }
    std::string dim = std::to_string(w) + "x" + std::to_string(h);
    return Response::ok(Json::obj({
        {"image_base64", Json::str(b64)},
        {"size",         Json::str(dim)},
        {"saved_path",   save_path.empty() ? Json::null_val() : Json::str(save_path)},
        {"format",       Json::str("bmp")},
    }));
#else
    return Response::err(501, "Screenshot only supported on Windows");
#endif
}

// Sentinel used to tell "content_b64 absent" from "content_b64 present
// but empty" — json_str's own default can't distinguish those since ""
// is a valid (if useless) empty-file write.
static const std::string CONTENT_B64_ABSENT = "\x01__absent__\x01";

static Response h_write_file(const Request& req) {
    std::string path_s = json_str(req.body, "path");
    if (path_s.empty()) return Response::err(400, "No path provided");
    fs::path p(path_s);
    Response blocked;
    if (reject_if_protected(p, blocked)) return blocked;

    std::string content_b64 = json_str(req.body, "content_b64", CONTENT_B64_ABSENT);
    if (content_b64 != CONTENT_B64_ABSENT) {
        std::vector<uint8_t> raw;
        if (!b64_decode(content_b64, raw)) {
            return Response::err(400, "Invalid base64 in content_b64");
        }
        try {
            fs::create_directories(p.parent_path());
            std::ofstream f(p, std::ios::binary);
            if (!f) return Response::err(500, "Cannot open file for writing");
            f.write((const char*)raw.data(), (std::streamsize)raw.size());
        } catch (std::exception& e) { return Response::err(500, e.what()); }
        return Response::ok(Json::obj({
            {"message", Json::str("Written to '" + path_s + "' (" + std::to_string(raw.size()) + " bytes, binary)")},
        }));
    }

    std::string content = json_str(req.body, "content");
    try {
        fs::create_directories(p.parent_path());
        std::ofstream f(p);
        if (!f) return Response::err(500, "Cannot open file for writing");
        f << content;
    } catch(std::exception& e) { return Response::err(500, e.what()); }
    return Response::ok(Json::obj({
        {"message", Json::str("Written to '" + path_s + "' (" + std::to_string(content.size()) + " bytes)")},
    }));
}

// Binary-safe counterpart to /preview (which reads/returns text). Lets
// file_transfer's pc: leg move binaries to/from a PC without corruption.
static Response h_read_file_b64(const Request& req) {
    std::string path_s = req.query.count("path") ? req.query.at("path") : "";
    size_t requested = req.query.count("max_bytes")
        ? (size_t)std::stoull(req.query.at("max_bytes"))
        : 10 * 1024 * 1024; // 10MB default
    if (path_s.empty()) return Response::err(400, "Missing 'path'");
    fs::path p(path_s);
    Response blocked;
    if (reject_if_protected(p, blocked)) return blocked;
    if (!fs::exists(p)) return Response::err(404, "Path does not exist: " + path_s);
    if (!fs::is_regular_file(p)) return Response::err(400, "Not a file");

    // Same finding-4 fix as h_preview: clamp to MAX_READ_BYTES and never
    // allocate more than the file actually contains.
    std::error_code ec;
    uintmax_t size = fs::file_size(p, ec);
    size_t max_bytes = std::min(requested, MAX_READ_BYTES);
    if (!ec) max_bytes = std::min(max_bytes, (size_t)size);

    std::ifstream f(p, std::ios::binary);
    if (!f) return Response::err(500, "Cannot open file");
    std::vector<uint8_t> buf(max_bytes);
    f.read((char*)buf.data(), (std::streamsize)max_bytes);
    buf.resize((size_t)f.gcount());

    bool truncated = !ec && size > buf.size();
    return Response::ok(Json::obj({
        {"path",           Json::str(path_s)},
        {"content_b64",    Json::str(b64_encode(buf))},
        {"size_bytes",     Json::num(ec ? (long long)buf.size() : (long long)size)},
        {"returned_bytes", Json::num((long long)buf.size())},
        {"truncated",      Json::boolean(truncated)},
    }));
}

// ---------------------------------------------------------------------------
// Local config / admin dashboard — see coordination/status/pc-agent.md and
// BROADCAST [0006]. Same access-control model as every other endpoint:
// loopback bind + optional ORGANISER_SECRET, not a separate auth scheme.
// ---------------------------------------------------------------------------

static Response h_get_config(const Request&) {
    const char* secret_env = getenv("ORGANISER_SECRET");
    const char* name_env = getenv("ORGANISER_MACHINE_NAME");
    std::string source = (secret_env && *secret_env) ? "env" : (!g_secret.empty() ? "config_file" : "none");
    return Response::ok(Json::obj({
        {"machine_id",     Json::str(g_machine_id)},
        {"machine_name",   Json::str(g_machine_name)},
        {"secret_set",     Json::boolean(!g_secret.empty())},
        {"secret_source",  Json::str(source)},
        {"config_path",    Json::str(g_machine_config_path.string())},
        {"name_env_set",   Json::boolean(name_env && *name_env)},
    }));
}

static Response h_post_config(const Request& req) {
    bool have_name = req.body.find("\"machine_name\"") != std::string::npos;
    bool have_secret = req.body.find("\"secret\"") != std::string::npos;
    if (!have_name && !have_secret) {
        return Response::err(400, "Nothing to update. Send machine_name and/or secret.");
    }

    // SECURITY_FINDINGS.md finding 20 (HIGH): /config previously let an
    // unauthenticated caller set the FIRST secret whenever none was
    // configured yet -- turning the transient "no secret = open" window
    // (finding 3, an accepted trade-off for one-off operations) into a
    // PERMANENT takeover, since the attacker-chosen secret then persists
    // to disk and locks the legitimate owner out on every future start.
    // Fix (the simplest of security-qa's suggested directions): /config
    // can ROTATE an existing secret (already safely gated -- reaching
    // this handler at all requires knowing the current secret once one
    // is set, via the normal auth check in handle_conn), but can never
    // BOOTSTRAP the first one over the network. The first secret must
    // come from ORGANISER_SECRET (env var) or a local edit of the
    // config file -- a step that requires actual local access, not just
    // network access to this port.
    if (have_secret) {
        std::string new_secret = json_str(req.body, "secret");
        if (g_secret.empty() && !new_secret.empty()) {
            return Response::err(403,
                "Cannot set the initial secret via /config over the network -- "
                "this would let anyone who reaches this port before you do "
                "permanently lock you out (SECURITY_FINDINGS.md finding 20). "
                "Set ORGANISER_SECRET as an environment variable (then restart), "
                "or edit " + g_machine_config_path.string() + " directly on this "
                "machine. Once a secret exists, /config can rotate it normally.");
        }
    }

    if (have_name) {
        std::string name = json_str(req.body, "machine_name");
        // trim
        size_t a = name.find_first_not_of(" \t");
        size_t b = name.find_last_not_of(" \t");
        name = (a == std::string::npos) ? "" : name.substr(a, b - a + 1);
        if (name.empty()) return Response::err(400, "machine_name cannot be empty");
        g_config_saved_name = name;
        const char* name_env = getenv("ORGANISER_MACHINE_NAME");
        if (!(name_env && *name_env)) g_machine_name = name;
    }

    if (have_secret) {
        // Empty string is allowed — removes the secret, matching
        // ORGANISER_SECRET-unset semantics. (The bootstrap guard above
        // only blocks empty->non-empty; non-empty->empty and
        // non-empty->non-empty rotation both still work, appropriately
        // gated by already needing the current secret to be here.)
        std::string secret = json_str(req.body, "secret");
        g_config_saved_secret = secret;
        const char* secret_env = getenv("ORGANISER_SECRET");
        if (!(secret_env && *secret_env)) g_secret = secret;
    }

    save_config_extras();
    return Response::ok(Json::obj({
        {"message",      Json::str("Config updated")},
        {"machine_name", Json::str(g_machine_name)},
        {"secret_set",   Json::boolean(!g_secret.empty())},
    }));
}

static Response h_admin_page(const Request&) {
    // No auth gate on the page shell itself (same reasoning as the Python
    // build): the shell contains no secrets, and every API call it makes
    // (/config) is separately auth-checked.
    static const char* html =
"<!DOCTYPE html><html><head><title>Organiser Agent - Local Config</title>"
"<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:40px auto}"
"label{display:block;margin-top:12px;font-weight:600}input{width:100%;padding:6px;"
"box-sizing:border-box}button{margin-top:16px;padding:8px 16px}"
"#status{margin-top:12px;white-space:pre-wrap;font-family:monospace;font-size:.85em}"
"</style></head><body>"
"<h2>Organiser Agent - Local Config</h2>"
"<p>Changes here are saved to this PC's local config file and take effect immediately.</p>"
"<label>Secret (X-Organiser-Secret, if one is set)<input id=\"authSecret\" type=\"password\"></label>"
"<hr>"
"<label>Machine name<input id=\"machineName\" type=\"text\"></label>"
"<label>New secret (leave blank to remove)<input id=\"newSecret\" type=\"password\"></label>"
"<p style=\"font-size:0.8em;color:#666\">If no secret is configured yet, it can't be set from this page over the network (security fix) - set ORGANISER_SECRET as an environment variable first, or edit the config file directly on this machine, then use this page to rotate it afterward.</p>"
"<button onclick=\"loadConfig()\">Refresh current config</button>"
"<button onclick=\"saveConfig()\">Save</button>"
"<div id=\"status\"></div>"
"<script>"
"async function call(path,opts){opts=opts||{};opts.headers=Object.assign({'Content-Type':'application/json'},opts.headers||{});"
"var s=document.getElementById('authSecret').value;if(s)opts.headers['X-Organiser-Secret']=s;"
"const r=await fetch(path,opts);const j=await r.json().catch(()=>({}));return{ok:r.ok,status:r.status,body:j};}"
"async function loadConfig(){const res=await call('/config');document.getElementById('status').textContent=JSON.stringify(res.body,null,2);"
"if(res.ok)document.getElementById('machineName').value=res.body.machine_name||'';}"
"async function saveConfig(){const updates={};const mn=document.getElementById('machineName').value.trim();"
"if(mn)updates.machine_name=mn;const ns=document.getElementById('newSecret');if(ns.value!=='')updates.secret=ns.value;"
"const res=await call('/config',{method:'POST',body:JSON.stringify(updates)});"
"document.getElementById('status').textContent=JSON.stringify(res.body,null,2);ns.value='';}"
"loadConfig();"
"</script></body></html>";
    Response r;
    r.status = 200;
    r.content_type = "text/html; charset=utf-8";
    r.body = html;
    return r;
}

// ---------------------------------------------------------------------------
// HTTP parsing and dispatch
// ---------------------------------------------------------------------------

static std::string status_text(int code) {
    switch(code) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 408: return "Request Timeout";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        default:  return "Unknown";
    }
}

// Constant-time string comparison for secret checks (SECURITY_FINDINGS.md
// finding 5: plain std::string != short-circuits on the first differing
// byte, a timing side channel). Matches the standard shape used by e.g.
// Python's hmac.compare_digest: length is compared normally (that alone
// isn't the sensitive part — the point is not leaking which *byte*
// differs), and every byte of the longer string is still visited even
// after a mismatch is found, so timing does not correlate with *where*
// two equal-length secrets first differ.
static bool constant_time_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); i++) {
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return diff == 0;
}

static void handle_conn(SOCKET sock) {
    // Read request into a growable buffer (SECURITY_FINDINGS.md finding 7:
    // this used to be a fixed 64KB stack buffer that silently stopped
    // once full, regardless of whether the declared Content-Length was
    // actually satisfied — a 200KB write_file body was confirmed to get
    // silently truncated to ~64KB with an HTTP 200 "success" response.
    // Fix: read headers first, size-check Content-Length against a hard
    // ceiling BEFORE committing to reading the whole body, then keep
    // reading (growing the buffer) until we've actually received exactly
    // as many bytes as declared — never fewer, silently.
    static const size_t MAX_HEADER_BYTES = 64 * 1024;       // plenty for any real HTTP header block
    static const size_t MAX_BODY_BYTES   = 25 * 1024 * 1024; // headroom over MAX_READ_BYTES for JSON/base64 overhead

    std::string raw;
    raw.reserve(8192);
    char chunk[8192];
    size_t header_end = std::string::npos;
    long long content_length = -1;
    size_t header_size = 0;

    // Phase 1: read until we have the full header block (\r\n\r\n).
    while (header_end == std::string::npos) {
        int n = recv(sock, chunk, sizeof(chunk), 0);
        if (n <= 0) { closesocket(sock); return; }
        raw.append(chunk, n);
        if (raw.size() > MAX_HEADER_BYTES) {
            // Header block itself is absurd — bail out rather than loop
            // forever waiting for a terminator that may never come.
            closesocket(sock);
            return;
        }
        header_end = raw.find("\r\n\r\n");
    }
    header_size = header_end + 4;

    {
        // Case-insensitive-enough search: real HTTP header names are
        // conventionally "Content-Length", but be tolerant of case since
        // this parser doesn't do full header normalization elsewhere either.
        size_t cl_pos = raw.find("Content-Length:");
        if (cl_pos == std::string::npos) cl_pos = raw.find("content-length:");
        if (cl_pos != std::string::npos && cl_pos < header_end) {
            content_length = atoll(raw.c_str() + cl_pos + 15);
        }
    }

    if (content_length > 0 && (size_t)content_length > MAX_BODY_BYTES) {
        // Reject BEFORE reading the (huge) body into memory at all.
        std::string ebody = Json::obj({{"error", Json::str(
            "Request body too large (" + std::to_string(content_length) +
            " bytes, max " + std::to_string(MAX_BODY_BYTES) + ")")}});
        std::string resp = "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                            + std::to_string(ebody.size()) + "\r\n\r\n" + ebody;
        send(sock, resp.c_str(), (int)resp.size(), 0);
        closesocket(sock);
        return;
    }

    // Phase 2: keep reading until we actually have header_size +
    // content_length bytes — not just until some fixed buffer fills up.
    size_t want_total = header_size + (content_length > 0 ? (size_t)content_length : 0);
    while (raw.size() < want_total) {
        int n = recv(sock, chunk, sizeof(chunk), 0);
        if (n <= 0) break; // connection closed early / short body — handle what we got
        raw.append(chunk, n);
    }
    if (content_length > 0 && raw.size() - header_size < (size_t)content_length) {
        // Client claimed a Content-Length it never actually sent (or the
        // connection dropped mid-body) — don't silently process a
        // truncated body as if it were complete.
        std::string ebody = Json::obj({{"error", Json::str("Connection closed before declared Content-Length was fully received")}});
        std::string resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                            + std::to_string(ebody.size()) + "\r\n\r\n" + ebody;
        send(sock, resp.c_str(), (int)resp.size(), 0);
        closesocket(sock);
        return;
    }

    if (raw.empty()) { closesocket(sock); return; }

    // Parse request line
    Request req;
    std::istringstream ss(raw);
    std::string line;
    std::getline(ss, line);
    if (!line.empty() && line.back()=='\r') line.pop_back();
    std::istringstream rl(line);
    std::string path_full;
    rl >> req.method >> path_full;

    // Split path and query string
    auto q = path_full.find('?');
    if (q != std::string::npos) {
        req.path  = path_full.substr(0, q);
        req.query = parse_qs(path_full.substr(q+1));
    } else {
        req.path = path_full;
    }

    // Parse headers
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back()=='\r') line.pop_back();
        if (line.empty()) break;
        auto col = line.find(':');
        if (col != std::string::npos) {
            std::string key = line.substr(0,col);
            std::string val = line.substr(col+1);
            while (!val.empty() && val[0]==' ') val = val.substr(1);
            std::transform(key.begin(),key.end(),key.begin(),::tolower);
            req.headers[key] = val;
        }
    }

    // Body
    auto body_pos = raw.find("\r\n\r\n");
    if (body_pos != std::string::npos)
        req.body = raw.substr(body_pos + 4);

    // Auth check — every route except the /admin page shell itself.
    // /admin's HTML contains no secrets and every API call it makes
    // (/config) is separately checked here like any other route; but the
    // page has to be loadable WITHOUT the secret first, or there'd be no
    // way to type the secret into its form in the first place. Matches
    // the equivalent comment in organiser-agent.py's admin_page().
    if (!g_secret.empty() && req.path != "/admin") {
        std::string hdr = req.headers.count("x-organiser-secret") ? req.headers.at("x-organiser-secret") : "";
        if (!constant_time_equal(hdr, g_secret)) {
            std::string ubody = "{\"error\":\"Unauthorized\"}";
            std::string resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: "
                                + std::to_string(ubody.size()) + "\r\n\r\n" + ubody;
            send(sock, resp.c_str(), (int)resp.size(), 0);
            closesocket(sock);
            return;
        }
    }

    // Handle OPTIONS
    if (req.method == "OPTIONS") {
        std::string resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\nContent-Length: 0\r\n\r\n";
        send(sock, resp.c_str(), (int)resp.size(), 0);
        closesocket(sock);
        return;
    }

    // Route
    std::string key = req.method + " " + req.path;
    Response res;
    if (g_routes.count(key)) {
        try { res = g_routes[key](req); }
        catch(std::exception& e) { res = Response::err(500, std::string("Exception: ") + e.what()); }
    } else {
        res = Response::err(404, "Not found: " + req.path);
    }

    // Send response
    std::string header = "HTTP/1.1 " + std::to_string(res.status) + " " + status_text(res.status) + "\r\n";
    header += "Content-Type: " + res.content_type + "\r\n";
    header += "Access-Control-Allow-Origin: *\r\n";
    header += "Content-Length: " + std::to_string(res.body.size()) + "\r\n\r\n";
    send(sock, header.c_str(), (int)header.size(), 0);
    send(sock, res.body.c_str(), (int)res.body.size(), 0);
    closesocket(sock);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    // Read config from env
    const char* port_env   = getenv("ORGANISER_PORT");
    const char* secret_env = getenv("ORGANISER_SECRET");
    if (port_env)   g_port   = atoi(port_env);
    if (secret_env) g_secret = secret_env;

    init_machine_registry();

    // Register routes
    add_route("GET",  "/status",       h_status);
    add_route("GET",  "/list",         h_list);
    add_route("POST", "/move",         h_move);
    add_route("POST", "/delete",       h_delete);
    add_route("GET",  "/preview",      h_preview);
    add_route("GET",  "/disk_usage",   h_disk_usage);
    add_route("POST", "/run_command",  h_run_command);
    add_route("GET",  "/duplicates",   h_duplicates);
    add_route("POST", "/screenshot",   h_screenshot);
    add_route("POST", "/write_file",   h_write_file);
    add_route("GET",  "/read_file_b64",h_read_file_b64);
    add_route("GET",  "/config",       h_get_config);
    add_route("POST", "/config",       h_post_config);
    add_route("GET",  "/admin",        h_admin_page);

    // Socket setup
#if IS_WIN
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == INVALID_SOCKET) {
        std::cerr << "Failed to create socket\n"; return 1;
    }
    int yes=1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

    sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(g_port);
    // Loopback-only: the SSH tunnel from the Linux server already targets
    // "localhost:7842" on this machine, so binding wider than 127.0.0.1
    // buys nothing except letting anyone else on the LAN reach this agent
    // directly (bypassing the tunnel and the ORGANISER_SECRET check if it's
    // ever left unset).
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(server, (sockaddr*)&addr, sizeof(addr)) != 0) {
        std::cerr << "Bind failed on port " << g_port << "\n"; return 1;
    }
    listen(server, 10);

    // Banner
    std::cout << "================================================\n";
    std::cout << "  Organiser Agent v" << VERSION << "\n";
    std::cout << "  Platform : " << platform_name() << "\n";
    std::cout << "  Machine  : " << g_machine_name << " (" << g_machine_id << ")\n";
    std::cout << "  Auth     : " << (g_secret.empty() ? "NO SECRET (open)" : "secret set") << "\n";
    std::cout << "  Listening: http://127.0.0.1:" << g_port << " (loopback only)\n";
    std::cout << "================================================\n";

    // Accept loop — one thread per connection (low traffic, so fine)
    while (true) {
        SOCKET client = accept(server, nullptr, nullptr);
        if (client == INVALID_SOCKET) continue;
        std::thread([client]() { handle_conn(client); }).detach();
    }

#if IS_WIN
    WSACleanup();
#endif
    return 0;
}
