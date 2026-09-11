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
static const char* VERSION  = "2.0.0-cpp";

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

// Run shell command, return stdout+stderr (capped at cap bytes)
static std::string run_command(const std::string& cmd, const std::string& cwd,
                               int& retcode, size_t cap = 8192) {
    std::string full_cmd = cmd;
    if (!cwd.empty()) {
#if IS_WIN
        full_cmd = "cd /d \"" + cwd + "\" && " + cmd;
#else
        full_cmd = "cd \"" + cwd + "\" && " + cmd;
#endif
    }
#if IS_WIN
    full_cmd = "cmd /c " + full_cmd + " 2>&1";
#else
    full_cmd = "/bin/bash -c '" + full_cmd + "' 2>&1";
#endif
    FILE* pipe =
#if IS_WIN
        _popen(full_cmd.c_str(), "r");
#else
        popen(full_cmd.c_str(), "r");
#endif
    if (!pipe) { retcode = -1; return "Failed to open pipe"; }
    std::string out;
    char buf[1024];
    while (fgets(buf, sizeof(buf), pipe) && out.size() < cap)
        out += buf;
    retcode =
#if IS_WIN
        _pclose(pipe);
#else
        pclose(pipe);
#endif
    if (out.size() > cap) out = out.substr(out.size() - cap);
    return out;
}

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
    size_t max_bytes = req.query.count("max_bytes") ? (size_t)std::stoull(req.query.at("max_bytes")) : 4096;
    if (path_s.empty()) return Response::err(400, "Missing 'path'");
    fs::path p(path_s);
    Response blocked;
    if (reject_if_protected(p, blocked)) return blocked;
    if (!fs::exists(p)) return Response::err(404, "Path does not exist: " + path_s);
    if (!fs::is_regular_file(p)) return Response::err(400, "Not a file");
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
    int rc = 0;
    std::string out = run_command(cmd, cwd, rc);
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
    int w=0, h=0;
    std::vector<uint8_t> data = screenshot_png(w, h);
    std::string b64 = b64_encode(data);
    std::string save_path = json_str(req.body, "save_path");
    if (!save_path.empty()) {
        std::ofstream f(save_path, std::ios::binary);
        if (f) f.write((char*)data.data(), data.size());
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

static Response h_write_file(const Request& req) {
    std::string path_s  = json_str(req.body, "path");
    std::string content = json_str(req.body, "content");
    if (path_s.empty()) return Response::err(400, "No path provided");
    fs::path p(path_s);
    Response blocked;
    if (reject_if_protected(p, blocked)) return blocked;
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

// ---------------------------------------------------------------------------
// HTTP parsing and dispatch
// ---------------------------------------------------------------------------

static std::string status_text(int code) {
    switch(code) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 404: return "Not Found";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        default:  return "Unknown";
    }
}

static void handle_conn(SOCKET sock) {
    // Read request (simple, not streaming — good for small API payloads)
    char buf[65536]; int total=0;
    while (total < (int)sizeof(buf)-1) {
        int n = recv(sock, buf+total, sizeof(buf)-1-total, 0);
        if (n <= 0) break;
        total += n;
        buf[total] = 0;
        // Stop when we have headers + body
        if (strstr(buf, "\r\n\r\n")) {
            // Check Content-Length for body
            const char* cl = strstr(buf, "Content-Length:");
            if (!cl) cl = strstr(buf, "content-length:");
            if (cl) {
                int clen = atoi(cl + 15);
                const char* body_start = strstr(buf, "\r\n\r\n");
                if (body_start) {
                    int header_size = (int)(body_start - buf) + 4;
                    if (total - header_size >= clen) break;
                }
            } else break;
        }
    }

    std::string raw(buf, total);
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

    // Auth check
    if (!g_secret.empty()) {
        std::string hdr = req.headers.count("x-organiser-secret") ? req.headers.at("x-organiser-secret") : "";
        if (hdr != g_secret) {
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
