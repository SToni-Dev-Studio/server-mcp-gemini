import { PLEX_URL, PLEX_TOKEN } from "../config.js";
import { MCPTool } from "../types.js";

export const plexTools: Record<string, MCPTool> = {
  plex_search: {
    name: "plex_search",
    description: "Search the Plex library for movies, shows, or anime by name.",
    inputSchema: {
      type: "object",
      required: ["query"],
      properties: { query: { type: "string" }, media_type: { type: "string" } },
    },
    handler: async ({ query }) => {
      if (!PLEX_TOKEN) return "PLEX_TOKEN not configured in environment.";
      try {
        const res = await fetch(
          `${PLEX_URL}/search?query=${encodeURIComponent(query)}&X-Plex-Token=${encodeURIComponent(PLEX_TOKEN)}`,
          {
            headers: { Accept: "application/json" },
            signal: AbortSignal.timeout(15000),
          }
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = (await res.json()) as any;
        const items = data.MediaContainer?.Metadata || [];
        if (items.length === 0) return `No results found for '${query}'.`;
        return items
          .slice(0, 10)
          .map((i: any) => `- [${i.ratingKey || ""}] ${i.title || "Unknown"} (${i.year || ""}) — ${i.type || ""}`)
          .join("\n");
      } catch (e: any) {
        return `Plex unreachable: ${e.message}`;
      }
    },
  },

  plex_get_libraries: {
    name: "plex_get_libraries",
    description: "List all Plex libraries (anime, movies, TV shows, etc.).",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      if (!PLEX_TOKEN) return "PLEX_TOKEN not configured in environment.";
      try {
        const res = await fetch(`${PLEX_URL}/library/sections?X-Plex-Token=${encodeURIComponent(PLEX_TOKEN)}`, {
          headers: { Accept: "application/json" },
          signal: AbortSignal.timeout(15000),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = (await res.json()) as any;
        const sections = data.MediaContainer?.Directory || [];
        if (sections.length === 0) return "No libraries found.";
        return sections.map((s: any) => `- [${s.key}] ${s.title} (${s.type})`).join("\n");
      } catch (e: any) {
        return `Plex unreachable: ${e.message}`;
      }
    },
  },

  plex_scan_library: {
    name: "plex_scan_library",
    description: "Trigger a Plex library scan to detect new anime/media files.",
    inputSchema: {
      type: "object",
      properties: { library_key: { type: "string", description: "all or specific key" } },
    },
    handler: async ({ library_key = "all" }) => {
      if (!PLEX_TOKEN) return "PLEX_TOKEN not configured in environment.";
      const path = library_key === "all" ? "/library/sections/all/refresh" : `/library/sections/${library_key}/refresh`;
      try {
        const res = await fetch(`${PLEX_URL}${path}?X-Plex-Token=${encodeURIComponent(PLEX_TOKEN)}`, {
          signal: AbortSignal.timeout(15000),
        });
        return `Library scan triggered (section: ${library_key}). Status: ${res.status}`;
      } catch (e: any) {
        return `Plex unreachable: ${e.message}`;
      }
    },
  },

  plex_get_status: {
    name: "plex_get_status",
    description: "Get Plex server status, version, and active sessions.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      if (!PLEX_TOKEN) return "PLEX_TOKEN not configured in environment.";
      try {
        const [infoRes, sessRes] = await Promise.all([
          fetch(`${PLEX_URL}/?X-Plex-Token=${encodeURIComponent(PLEX_TOKEN)}`, {
            headers: { Accept: "application/json" },
            signal: AbortSignal.timeout(15000),
          }),
          fetch(`${PLEX_URL}/status/sessions?X-Plex-Token=${encodeURIComponent(PLEX_TOKEN)}`, {
            headers: { Accept: "application/json" },
            signal: AbortSignal.timeout(15000),
          }),
        ]);
        const info = ((await infoRes.json()) as any).MediaContainer || {};
        const sess = ((await sessRes.json()) as any).MediaContainer || {};
        const active = sess.Metadata || [];
        const lines = [
          `**Plex Server:** ${info.friendlyName || "Unknown"}`,
          `**Version:** ${info.version || "Unknown"}`,
          `**Active Sessions:** ${sess.size || 0}`,
        ];
        for (const s of active) {
          lines.push(`  - ${s.User?.title || "Unknown"} watching '${s.title || "Unknown"}' (${s.Player?.state || "unknown"})`);
        }
        return lines.join("\n");
      } catch (e: any) {
        return `Plex unreachable: ${e.message}`;
      }
    },
  },

  plex_get_recently_added: {
    name: "plex_get_recently_added",
    description: "Get recently added media in Plex library.",
    inputSchema: {
      type: "object",
      properties: { count: { type: "number" } },
    },
    handler: async ({ count = 10 }) => {
      if (!PLEX_TOKEN) return "PLEX_TOKEN not configured in environment.";
      try {
        const res = await fetch(
          `${PLEX_URL}/library/recentlyAdded?X-Plex-Token=${encodeURIComponent(PLEX_TOKEN)}&X-Plex-Container-Size=${count}`,
          { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(15000) }
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = (await res.json()) as any;
        const items = data.MediaContainer?.Metadata || [];
        if (items.length === 0) return "No recently added media.";
        return items.map((i: any) => `- ${i.title || "Unknown"} (${i.type || ""}) — added: ${i.addedAt || ""}`).join("\n");
      } catch (e: any) {
        return `Plex unreachable: ${e.message}`;
      }
    },
  },
};
