import { sshServer } from "../ssh.js";
import { shQuote } from "../security.js";
import { MCPTool } from "../types.js";

export const serverTools: Record<string, MCPTool> = {
  server_status: {
    name: "server_status",
    description: "Get status of all services on the home Linux server (Plex, Sonarr, qBittorrent, etc.).",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const cmd =
        "systemctl is-active plexmediaserver sonarr jackett qbittorrent plex-watch 2>&1 | paste - - - - - | awk '{print \"plexmediaserver:\", $1, \"| sonarr:\", $2, \"| jackett:\", $3, \"| qbittorrent:\", $4, \"| plex-watch:\", $5}'";
      const result = await sshServer(cmd);
      const disk = await sshServer("df -h / /mnt/ssd 2>/dev/null | tail -2");
      const ram = await sshServer("free -h 2>/dev/null | grep Mem");
      return `**Services:**\n${result}\n\n**Disk:**\n${disk}\n\n**RAM:**\n${ram}`;
    },
  },

  server_download_anime: {
    name: "server_download_anime",
    description: "Search for and queue an anime download on the home server via Sonarr.",
    inputSchema: {
      type: "object",
      required: ["anime_name"],
      properties: {
        anime_name: { type: "string" },
        sonarr_quality: { type: "string", description: "Quality profile, defaults to Any" },
      },
    },
    handler: async ({ anime_name }) => {
      const sonarrKeyCmd = "cat /var/lib/sonarr/config.xml 2>/dev/null | grep -o '<ApiKey>[^<]*</ApiKey>' | sed 's/<[^>]*>//g'";
      const apiKey = (await sshServer(sonarrKeyCmd)).trim();
      if (!apiKey) {
        return "Could not retrieve Sonarr API key from server.";
      }

      const pySource = `
import urllib.request as u, urllib.parse as p, json
term = p.quote(${JSON.stringify(anime_name)})
url = "http://localhost:8989/api/v3/series/lookup?term=" + term + "&apikey=${apiKey}"
try:
    with u.urlopen(url, timeout=15) as r:
        data = json.load(r)
    for i, s in enumerate(data[:5]):
        print(f"{i}: {s.get('title','?')} ({s.get('year','?')}) - tvdbId={s.get('tvdbId','?')}")
except Exception as e:
    print(f"Error querying Sonarr: {e}")
`;
      const srcB64 = Buffer.from(pySource, "utf-8").toString("base64");
      const results = await sshServer(`echo '${srcB64}' | base64 -d | python3 -`);
      return `**Sonarr search results for '${anime_name}':**\n${results}\n\nTo add one, say 'add anime [number] from this list' and I'll queue it up!`;
    },
  },

  server_download_status: {
    name: "server_download_status",
    description: "Check current download status in qBittorrent and pipeline log.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const downloads = await sshServer("ls -lh /mnt/ssd/plex/downloads/ 2>/dev/null | head -20");
      const library = await sshServer("ls /media/plex/anime/library/ 2>/dev/null | head -20");
      const log = await sshServer("tail -20 /var/log/plex-download.log 2>/dev/null");
      return (
        `**Active Downloads (/mnt/ssd/plex/downloads):**\n${downloads || "Empty"}\n\n` +
        `**Anime Library (/media/plex/anime/library):**\n${library || "Empty"}\n\n` +
        `**Pipeline Log (last 20 lines):**\n${log || "No log yet"}`
      );
    },
  },

  server_run_command: {
    name: "server_run_command",
    description: "Run a shell command on the home Linux server over SSH.",
    inputSchema: {
      type: "object",
      required: ["command"],
      properties: { command: { type: "string" } },
    },
    handler: async ({ command }) => {
      return await sshServer(command);
    },
  },

  server_pipeline_log: {
    name: "server_pipeline_log",
    description: "Get the full recent pipeline log showing download, scan, compress, and backup activity.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      return await sshServer("tail -50 /var/log/plex-download.log 2>/dev/null || echo '(log file not found)'");
    },
  },

  server_list_files: {
    name: "server_list_files",
    description: "List files and directories at a path on the Linux server.",
    inputSchema: {
      type: "object",
      required: ["path"],
      properties: { path: { type: "string" }, recursive: { type: "boolean" } },
    },
    handler: async ({ path, recursive = false }) => {
      const cmd = recursive
        ? `find ${shQuote(path)} -maxdepth 3 -not -path '*/.*' 2>/dev/null | sort | head -200`
        : `ls -lhA ${shQuote(path)} 2>&1 | head -100`;
      return await sshServer(cmd);
    },
  },

  server_disk_usage: {
    name: "server_disk_usage",
    description: "Show disk usage breakdown on the Linux server, sorted largest-first.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
    },
    handler: async ({ path = "/" }) => {
      const overview = await sshServer("df -h");
      const breakdown = await sshServer(`du -h --max-depth=2 ${shQuote(path)} 2>/dev/null | sort -rh | head -30`);
      return `**Filesystem overview:**\n${overview}\n\n**Breakdown of ${path}:**\n${breakdown}`;
    },
  },

  server_read_file: {
    name: "server_read_file",
    description: "Read a file on the Linux server. Specify tail=N or head=N lines, or neither for first 200 lines.",
    inputSchema: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string" },
        tail: { type: "number" },
        head: { type: "number" },
      },
    },
    handler: async ({ path, tail = 0, head = 0 }) => {
      let cmd: string;
      if (tail) {
        cmd = `tail -n ${shQuote(tail)} ${shQuote(path)} 2>&1`;
      } else if (head) {
        cmd = `head -n ${shQuote(head)} ${shQuote(path)} 2>&1`;
      } else {
        cmd = `head -n 200 ${shQuote(path)} 2>&1`;
      }
      return await sshServer(cmd);
    },
  },

  server_write_file: {
    name: "server_write_file",
    description: "Write (overwrite) a file on the Linux server via safe base64 transfer.",
    inputSchema: {
      type: "object",
      required: ["path", "content"],
      properties: {
        path: { type: "string" },
        content: { type: "string" },
      },
    },
    handler: async ({ path, content }) => {
      const encoded = Buffer.from(content, "utf-8").toString("base64");
      const cmd = `mkdir -p $(dirname ${shQuote(path)}) && echo ${shQuote(encoded)} | base64 -d > ${shQuote(path)} && echo 'OK'`;
      const result = await sshServer(cmd);
      return `Written to '${path}': ${result}`;
    },
  },

  server_move_file: {
    name: "server_move_file",
    description: "Move or rename a file or directory on the Linux server.",
    inputSchema: {
      type: "object",
      required: ["source", "destination"],
      properties: { source: { type: "string" }, destination: { type: "string" } },
    },
    handler: async ({ source, destination }) => {
      return await sshServer(`mv ${shQuote(source)} ${shQuote(destination)} && echo 'Moved OK'`);
    },
  },

  server_delete_file: {
    name: "server_delete_file",
    description: "Delete a single file (not a directory) on the Linux server.",
    inputSchema: {
      type: "object",
      required: ["path"],
      properties: { path: { type: "string" } },
    },
    handler: async ({ path }) => {
      return await sshServer(`rm ${shQuote(path)} && echo 'Deleted OK'`);
    },
  },

  server_process_list: {
    name: "server_process_list",
    description: "Show top CPU and RAM consuming processes on the Linux server.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      return await sshServer("ps aux --sort=-%cpu | head -20");
    },
  },

  server_service_control: {
    name: "server_service_control",
    description: "Start, stop, restart, or check status of a systemd service on the Linux server.",
    inputSchema: {
      type: "object",
      required: ["service", "action"],
      properties: {
        service: { type: "string" },
        action: {
          type: "string",
          enum: ["start", "stop", "restart", "status", "enable", "disable"],
        },
      },
    },
    handler: async ({ service, action }) => {
      const allowed = ["start", "stop", "restart", "status", "enable", "disable"];
      if (!allowed.includes(action)) {
        return `Invalid action '${action}'. Must be one of: ${allowed.join(", ")}`;
      }
      return await sshServer(`sudo systemctl ${action} ${shQuote(service)} 2>&1`);
    },
  },

  server_tail_log: {
    name: "server_tail_log",
    description: "Tail any log file on the Linux server (e.g. /var/log/syslog, /var/log/plex-download.log).",
    inputSchema: {
      type: "object",
      required: ["log_path"],
      properties: { log_path: { type: "string" }, lines: { type: "number" } },
    },
    handler: async ({ log_path, lines = 50 }) => {
      return await sshServer(`tail -n ${shQuote(lines)} ${shQuote(log_path)} 2>&1`);
    },
  },

  server_cron_list: {
    name: "server_cron_list",
    description: "List all cron jobs on the Linux server (user + root + system /etc/cron.d).",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const userCron = await sshServer("crontab -l 2>/dev/null || echo '(no user crontab)'");
      const rootCron = await sshServer("sudo crontab -l 2>/dev/null || echo '(no root crontab)'");
      const systemCron = await sshServer("ls /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null | head -60");
      return `**User crontab:**\n${userCron}\n\n**Root crontab:**\n${rootCron}\n\n**System cron.d:**\n${systemCron}`;
    },
  },

  server_network_info: {
    name: "server_network_info",
    description: "Show network interfaces, open ports, and active connections on the Linux server.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const interfaces = await sshServer("ip -brief addr 2>/dev/null || ifconfig");
      const ports = await sshServer("ss -tlnp 2>/dev/null | head -30");
      const connections = await sshServer("ss -tnp state established 2>/dev/null | head -20");
      return `**Interfaces:**\n${interfaces}\n\n**Listening ports:**\n${ports}\n\n**Active connections:**\n${connections}`;
    },
  },

  server_docker_status: {
    name: "server_docker_status",
    description: "List Docker containers and images on the Linux server (if Docker is installed).",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const containers = await sshServer("docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}' 2>&1");
      const images = await sshServer("docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}' 2>&1 | head -20");
      return `**Containers:**\n${containers}\n\n**Images:**\n${images}`;
    },
  },

  server_find_duplicates: {
    name: "server_find_duplicates",
    description: "Find duplicate files on the Linux server by content hash (MD5).",
    inputSchema: {
      type: "object",
      required: ["path"],
      properties: { path: { type: "string" } },
    },
    handler: async ({ path }) => {
      const cmd = `find ${shQuote(path)} -type f -exec md5sum {} + 2>/dev/null | sort | awk 'seen[$1]++{print $2, "DUPLICATE OF", prev[$1]} {prev[$1]=$2}' | head -40`;
      const result = await sshServer(cmd);
      return result || "No duplicates found.";
    },
  },
};
