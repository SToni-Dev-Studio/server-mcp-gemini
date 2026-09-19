# Gemini MCP Build Notes

This repo was bootstrapped and retargeted for Gemini MCP Server:

`https://github.com/mienkek13-netizen/server-mcp-gemini`

## Built locally

### 1. Debian hub tools package (`.deb`)

```bash
bash packaging/build-deb.sh 0.1.0-gemini
```

Output:

```text
packaging/mcp-hub-tools_0.1.0-gemini_all.deb
packaging/mcp-hub-tools_0.1.0-gemini_all.deb.sha256
```

### 2. Native Linux organiser-agent binary

```bash
mkdir -p dist
g++ -std=c++17 -O2 -Wall -o dist/organiser-agent-linux organiser-agent.cpp -lpthread
```

Output:

```text
dist/organiser-agent-linux
```

### 3. Windows organiser-agent binary (`.exe`)

On Windows (MSVC / Visual Studio Developer Prompt):

```cmd
cl /EHsc /O2 /std:c++17 organiser-agent.cpp /Fe:dist\organiser-agent.exe
```

On Linux with MinGW-w64 cross-compiler installed:

```bash
x86_64-w64-mingw32-g++ -std=c++17 -O2 -Wall -static -o dist/organiser-agent.exe organiser-agent.cpp -lws2_32 -lshell32 -lgdi32 -luser32
```

## Local Installation of .deb

The `.deb` package was compiled and installed for the user environment:
- Package file: `packaging/mcp-hub-tools_0.1.0-gemini_all.deb`
- Installed executables and scripts: `~/.local/lib/mcp-hub-tools/`, `~/.local/bin/hub-cli`, `~/.local/bin/hub-diagnostics`
- System-wide installation (with sudo): `sudo dpkg -i packaging/mcp-hub-tools_0.1.0-gemini_all.deb`
