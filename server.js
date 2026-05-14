const EMBED_SECRET = "bangbot-dev-secret-change-me";

const playlistMimeTypes = [
  "application/vnd.apple.mpegurl",
  "application/x-mpegurl",
  "audio/mpegurl",
  "audio/x-mpegurl",
];

const dashMimeTypes = [
  "application/dash+xml",
  "video/vnd.mpeg.dash.mpd",
];

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, range",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
};

function logError(scope, details) {
  console.error(`[${new Date().toISOString()}] ${scope}`, details);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function parseBoolean(value, defaultValue = false) {
  if (value == null || value === "") return defaultValue;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function base64UrlEncodeBytes(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlEncodeString(value) {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

function base64UrlDecodeBytes(value) {
  const normalized = String(value).replaceAll("-", "+").replaceAll("_", "/");
  const padding = "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = atob(normalized + padding);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function getSecretKey(secret) {
  const keyBytes = new TextEncoder().encode(secret || EMBED_SECRET);
  const digest = await crypto.subtle.digest("SHA-256", keyBytes);
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function createToken(payload, secret) {
  const key = await getSecretKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedPayload = new TextEncoder().encode(JSON.stringify(payload));
  const cipherBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encodedPayload);
  const cipherBytes = new Uint8Array(cipherBuffer);
  const tagLength = 16;
  const encrypted = cipherBytes.slice(0, cipherBytes.length - tagLength);
  const tag = cipherBytes.slice(cipherBytes.length - tagLength);
  return [base64UrlEncodeBytes(iv), base64UrlEncodeBytes(tag), base64UrlEncodeBytes(encrypted)].join(".");
}

async function decodeToken(token, secret) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;

  try {
    const [iv, tag, encrypted] = parts.map(base64UrlDecodeBytes);
    const key = await getSecretKey(secret);
    const combined = new Uint8Array(encrypted.length + tag.length);
    combined.set(encrypted, 0);
    combined.set(tag, encrypted.length);
    const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, combined);
    return JSON.parse(new TextDecoder().decode(plainBuffer));
  } catch {
    return null;
  }
}

function getHeaderValue(header) {
  return String(header || "").split(",")[0].trim();
}

function getPublicOrigin(request, requestUrl) {
  const proto = getHeaderValue(request.headers.get("x-forwarded-proto")) || requestUrl.protocol.replace(":", "");
  const host = getHeaderValue(request.headers.get("x-forwarded-host")) || request.headers.get("host") || requestUrl.host;
  return `${proto}://${host}`;
}

function validateSource(rawSource) {
  if (!rawSource) return { error: "Parameter 'src' wajib diisi." };
  if (rawSource.includes("/http://") || rawSource.includes("/https://")) {
    return { error: "Parameter 'src' terlihat malformed atau terduplikasi." };
  }

  try {
    const parsed = new URL(rawSource);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return { error: "Hanya URL http/https yang didukung." };
    }
    return { sourceUrl: parsed.toString() };
  } catch {
    return { error: "Parameter 'src' harus berupa URL yang valid." };
  }
}

function guessStreamType(sourceUrl) {
  const pathname = new URL(sourceUrl).pathname.toLowerCase();
  if (pathname.endsWith(".m3u8")) return "hls";
  if (pathname.endsWith(".mpd")) return "dash";
  return "unknown";
}

function parseHeaderLines(rawHeaders) {
  const headers = {};
  const input = String(rawHeaders || "").trim();
  if (!input) return headers;

  input.split(/\r?\n/).forEach((line) => {
    const trimmed = line.trim();
    const separatorIndex = trimmed.indexOf(":");
    if (separatorIndex <= 0) return;
    const name = trimmed.slice(0, separatorIndex).trim().toLowerCase();
    const value = trimmed.slice(separatorIndex + 1).trim();
    if (name && value) headers[name] = value;
  });

  return headers;
}

function getSourcePreset(sourceUrl) {
  try {
    const parsed = new URL(sourceUrl);
    const hostname = parsed.hostname.toLowerCase();

    if (hostname.endsWith(".dens.tv") || hostname === "dens.tv") {
      return {
        referer: sourceUrl,
        cookie: "perf_dv6Tr4n=1",
        headers: [
          "Accept: */*",
          "Accept-Encoding: identity;q=1, *;q=0",
          "Accept-Language: en-US,en;q=0.9,id-ID;q=0.8,id;q=0.7",
          "Cache-Control: no-cache",
          "Pragma: no-cache",
          "Priority: i",
          'Sec-CH-UA: "Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
          "Sec-CH-UA-Mobile: ?0",
          'Sec-CH-UA-Platform: "Windows"',
          "Sec-Fetch-Dest: video",
          "Sec-Fetch-Mode: no-cors",
          "Sec-Fetch-Site: same-origin",
          "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        ].join("\n"),
      };
    }

    return {
      referer: `${parsed.origin}/`,
      cookie: "",
      headers: "",
    };
  } catch {
    return { referer: "", cookie: "", headers: "" };
  }
}

function createProxyOptions(sourceUrl, params = {}) {
  const preset = getSourcePreset(sourceUrl);
  return {
    referer: params.referer || preset.referer || "",
    cookie: params.cookie || preset.cookie || "",
    headers: params.headers || preset.headers || "",
  };
}

async function createProxyToken(url, options, secret) {
  return createToken({
    proxyUrl: url,
    referer: options.referer || "",
    cookie: options.cookie || "",
    headers: options.headers || "",
  }, secret);
}

async function getProxyUrl(origin, url, options, secret) {
  const token = await createProxyToken(url, options, secret);
  return `${origin}/proxy?token=${encodeURIComponent(token)}`;
}

async function rewriteHlsManifest(manifestText, baseUrl, origin, proxyOptions, secret) {
  const lines = manifestText.split(/\r?\n/);
  const rewrittenLines = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      rewrittenLines.push(line);
      continue;
    }

    if (trimmed.startsWith("#")) {
      const rewritten = line.replace(/URI="([^"]+)"/g, (_match, uri) => {
        const absoluteUrl = new URL(uri, baseUrl).toString();
        return `URI="${origin}/proxy?token=${encodeURIComponent("")}"`.replace(
          `${origin}/proxy?token=${encodeURIComponent("")}`,
          ""
        );
      });

      let nextLine = rewritten;
      const matches = [...rewritten.matchAll(/URI="([^"]+)"/g)];
      for (const match of matches) {
        const absoluteUrl = new URL(match[1], baseUrl).toString();
        const proxyUrl = await getProxyUrl(origin, absoluteUrl, proxyOptions, secret);
        nextLine = nextLine.replace(`URI="${match[1]}"`, `URI="${proxyUrl}"`);
      }
      rewrittenLines.push(nextLine);
      continue;
    }

    const absoluteUrl = new URL(trimmed, baseUrl).toString();
    rewrittenLines.push(await getProxyUrl(origin, absoluteUrl, proxyOptions, secret));
  }

  return rewrittenLines.join("\n");
}

async function rewriteDashManifest(manifestText, baseUrl, origin, proxyOptions, secret) {
  let output = manifestText;
  const baseUrlMatches = [...output.matchAll(/<BaseURL>([^<]+)<\/BaseURL>/g)];
  for (const match of baseUrlMatches) {
    const absoluteUrl = new URL(match[1].trim(), baseUrl).toString();
    const proxyUrl = await getProxyUrl(origin, absoluteUrl, proxyOptions, secret);
    output = output.replace(match[0], `<BaseURL>${proxyUrl}</BaseURL>`);
  }

  const attrRegex = /\b(initialization|media|sourceURL|href|url)="([^"]+)"/g;
  const attrMatches = [...output.matchAll(attrRegex)];
  for (const match of attrMatches) {
    const value = match[2];
    if (!value || value.startsWith("$") || value.startsWith("urn:") || value.startsWith("data:")) continue;
    const absoluteUrl = new URL(value.trim(), baseUrl).toString();
    const proxyUrl = await getProxyUrl(origin, absoluteUrl, proxyOptions, secret);
    output = output.replace(`${match[1]}="${value}"`, `${match[1]}="${proxyUrl}"`);
  }

  return output;
}

function buildLandingPage(origin, secret) {
  const hlsSource = "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8";
  const dashSource = "https://dash.akamaized.net/envivio/EnvivioDash3/manifest.mpd";
  return {
    name: "embedstreaming",
    status: "ok",
    endpoints: {
      health: "/health",
      embed: "/embed?src=<stream-url>&type=<auto|hls|dash>",
      sign: "/sign?src=<stream-url>&type=<auto|hls|dash>",
    },
    examples: {
      hls: `${origin}/embed?src=${encodeURIComponent(hlsSource)}`,
      dash: `${origin}/embed?src=${encodeURIComponent(dashSource)}`,
      tokenizedHls: `${origin}/embed?token=<generated-by-sign>`,
    },
    notes: [
      "Endpoint /sign mengembalikan URL embed dengan token terenkripsi.",
      "Source tertentu seperti Dens TV otomatis memakai preset proxy.",
      `EMBED_SECRET aktif: ${Boolean(secret) ? "yes" : "fallback-default"}`,
    ],
  };
}

function buildEmbedHtml({ sourceUrl, playbackUrl, streamType, autoplay, muted, controls, title, engine }) {
  const safeTitle = escapeHtml(title || "BangBot Player");
  const safeSource = JSON.stringify(playbackUrl || sourceUrl);
  const safeType = JSON.stringify(streamType);
  const safeEngine = JSON.stringify(engine);
  const safeAutoplay = autoplay ? "true" : "false";
  const safeMuted = muted ? "true" : "false";
  const safeControls = controls ? "true" : "false";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${safeTitle}</title>
    <style>
      :root {
        color-scheme: dark;
        font-family: "Segoe UI", Arial, sans-serif;
        --text-main: #f8fafc;
        --glass-border: rgba(255,255,255,.14);
      }
      * { box-sizing: border-box; }
      html, body { margin: 0; width: 100%; height: 100%; overflow: hidden; background: #020617; color: var(--text-main); }
      body { display: grid; place-items: center; padding: 18px; }
      .player-shell {
        position: relative;
        width: min(100%, 960px);
        aspect-ratio: var(--frame-ratio, 16 / 9);
        max-height: calc(100vh - 36px);
        display: grid;
        place-items: center;
        border-radius: 28px;
        overflow: hidden;
        background: #000;
        box-shadow: 0 24px 80px rgba(0,0,0,.45), 0 0 0 1px rgba(255,255,255,.06);
      }
      video { width: 100%; height: 100%; background: #000; object-fit: contain; object-position: center center; }
      .overlay {
        position: absolute; inset: 0; display: block;
        background: linear-gradient(180deg, rgba(2,6,23,.28) 0%, rgba(2,6,23,.08) 24%, rgba(2,6,23,.42) 100%);
        pointer-events: none; transition: background .22s ease;
      }
      .overlay.is-playing { background: transparent; }
      .brand-corner {
        position: absolute; top: 14px; left: 14px; padding: 9px 13px; border: 1px solid var(--glass-border);
        border-radius: 999px; background: rgba(15,23,42,.62); backdrop-filter: blur(12px); color: var(--text-main);
        font-size: 11px; font-weight: 600; letter-spacing: .16em; text-transform: uppercase; box-shadow: 0 12px 30px rgba(2,6,23,.26);
      }
      .live-corner { position: absolute; top: 14px; right: 14px; z-index: 3; pointer-events: none; }
      .live-pill {
        display: inline-flex; align-items: center; gap: 7px; min-width: 62px; padding: 0 10px; height: 30px; border-radius: 999px;
        background: rgba(255,255,255,.08); color: rgba(248,250,252,.94); font-size: 11px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase;
      }
      .live-pill::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: #ef4444; box-shadow: 0 0 12px rgba(239,68,68,.78); }
      .center-play { position: absolute; inset: 0; display: grid; place-items: center; pointer-events: none; transition: opacity .22s ease; }
      .center-stack { display: grid; justify-items: center; pointer-events: auto; }
      .play-button {
        appearance: none; border: 0; width: 84px; height: 84px; border-radius: 999px; background: rgba(255,255,255,.92); color: #0f172a;
        cursor: pointer; box-shadow: 0 18px 45px rgba(2,6,23,.38), 0 0 0 14px rgba(255,255,255,.08);
        transition: transform .18s ease, box-shadow .18s ease, opacity .18s ease; pointer-events: auto; position: relative;
      }
      .play-button svg { width: 34px; height: 34px; display: block; margin: 0 auto; overflow: visible; }
      .play-spinner {
        position: absolute; inset: 50% auto auto 50%; width: 34px; height: 34px; margin: -17px 0 0 -17px; border-radius: 50%;
        border: 3px solid rgba(15,23,42,.18); border-top-color: rgba(15,23,42,.92); opacity: 0; transform: scale(.72);
        transition: opacity .18s ease, transform .18s ease; animation: spin .9s linear infinite; pointer-events: none;
      }
      .play-icon-play, .play-icon-pause-left, .play-icon-pause-right { transform-box: fill-box; transform-origin: center; transition: transform .22s ease, opacity .22s ease; }
      .play-icon-play { transform: scale(1) translateX(0); opacity: 1; }
      .play-icon-pause-left, .play-icon-pause-right { opacity: 0; }
      .play-icon-pause-left { transform: translateX(-3px) scaleY(.7); }
      .play-icon-pause-right { transform: translateX(3px) scaleY(.7); }
      .play-button.is-playing .play-icon-play { transform: scale(.55); opacity: 0; }
      .play-button.is-playing .play-icon-pause-left, .play-button.is-playing .play-icon-pause-right { opacity: 1; transform: translateX(0) scaleY(1); }
      .play-button.is-buffering .play-icon-play, .play-button.is-buffering .play-icon-pause-left, .play-button.is-buffering .play-icon-pause-right { opacity: 0; transform: scale(.5); }
      .play-button.is-buffering .play-spinner { opacity: 1; transform: scale(1); }
      .pulse-ring { position: absolute; width: 84px; height: 84px; border-radius: 999px; border: 1px solid rgba(255,255,255,.32); background: rgba(255,255,255,.08); opacity: 0; transform: scale(.88); pointer-events: none; }
      .pulse-ring.active { animation: pulse-ring .42s ease-out; }
      .controls-shell {
        position: absolute; left: 0; right: 0; bottom: 0; padding: 32px 16px 14px;
        background: linear-gradient(180deg, rgba(2,6,23,0) 0%, rgba(2,6,23,.82) 72%);
        pointer-events: none; opacity: 1; transform: translateY(0); transition: opacity .22s ease, transform .22s ease;
      }
      .controls-shell.hidden { opacity: 0; transform: translateY(12px); }
      .seek-wrap, .control-row { pointer-events: auto; }
      .seek-wrap { display: grid; margin-bottom: 14px; }
      .seekbar, .volume-slider {
        -webkit-appearance: none; appearance: none; width: 100%; height: 6px; border-radius: 999px; outline: none;
        background: linear-gradient(90deg, rgba(248,250,252,.96) var(--value, 0%), rgba(255,255,255,.22) var(--value, 0%)); cursor: pointer;
      }
      .seekbar::-webkit-slider-thumb, .volume-slider::-webkit-slider-thumb {
        -webkit-appearance: none; appearance: none; width: 14px; height: 14px; border-radius: 50%; border: 0; background: #fff; box-shadow: 0 2px 10px rgba(0,0,0,.28);
      }
      .control-row { display: flex; align-items: center; justify-content: space-between; gap: 14px; min-width: 0; }
      .control-group { display: flex; align-items: center; gap: 10px; min-width: 0; }
      .control-group.right { margin-left: auto; justify-content: flex-end; }
      .control-btn {
        display: inline-grid; place-items: center; width: 40px; height: 40px; padding: 0; border: 0; border-radius: 999px;
        background: rgba(255,255,255,.08); color: #f8fafc; cursor: pointer; transition: transform .16s ease, background .16s ease;
      }
      .control-btn svg { width: 18px; height: 18px; fill: currentColor; }
      .time-label { color: rgba(248,250,252,.94); font-size: 13px; font-variant-numeric: tabular-nums; white-space: nowrap; text-align: right; }
      .volume-wrap { display: flex; align-items: center; gap: 10px; width: 0; overflow: hidden; opacity: 0; transform: translateX(-6px); transition: width .18s ease, opacity .18s ease, transform .18s ease; }
      .volume-wrap.open { width: 132px; opacity: 1; transform: translateX(0); }
      .overlay.is-playing .center-play { opacity: 0; }
      .overlay.is-hovered .center-play, .overlay.is-paused .center-play { opacity: 1; }
      video[hidden], .overlay[hidden] { display: none; }
      @keyframes pulse-ring { 0% { opacity: .5; transform: scale(.88); } 100% { opacity: 0; transform: scale(1.45); } }
      @keyframes spin { to { transform: rotate(360deg); } }
      @media (max-width: 640px) {
        body { padding: 0; }
        .play-button, .pulse-ring { width: 78px; height: 78px; }
        .player-shell { width: 100%; max-height: 100vh; border-radius: 0; }
        .brand-corner, .live-corner { top: 10px; }
        .brand-corner { left: 10px; font-size: 10px; padding: 8px 11px; }
        .live-corner { right: 10px; }
        .controls-shell { padding: 28px 10px 10px; }
        .control-row { gap: 8px; }
        .control-btn { width: 36px; height: 36px; }
        .volume-wrap.open { width: 72px; }
        .time-label { font-size: 12px; }
      }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
    <script src="https://cdn.dashjs.org/latest/dash.all.min.js"></script>
  </head>
  <body>
    <main class="player-shell">
      <video id="player" playsinline ${autoplay ? "autoplay" : ""} ${muted ? "muted" : ""}></video>
      <div id="overlay" class="overlay">
        <div class="brand-corner">BangBot Player</div>
        <div class="live-corner"><div id="livePill" class="live-pill" hidden>Live</div></div>
        <div class="center-play">
          <div class="center-stack">
            <div id="pulseRing" class="pulse-ring" aria-hidden="true"></div>
            <button id="playButton" class="play-button" type="button" aria-label="Play video">
              <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path class="play-icon-play" d="M8 5.14v13.72c0 .77.83 1.25 1.5.86l10.5-6.86a1 1 0 0 0 0-1.72L9.5 4.28A1 1 0 0 0 8 5.14Z"></path>
                <rect class="play-icon-pause-left" x="7.2" y="5.2" width="3.6" height="13.6" rx="1.2"></rect>
                <rect class="play-icon-pause-right" x="13.2" y="5.2" width="3.6" height="13.6" rx="1.2"></rect>
              </svg>
              <span class="play-spinner" aria-hidden="true"></span>
            </button>
          </div>
        </div>
        <div id="controlsShell" class="controls-shell ${controls ? "" : "hidden"}">
          <div class="seek-wrap"><input id="seekbar" class="seekbar" type="range" min="0" max="1000" value="0" step="1" aria-label="Seek" /></div>
          <div class="control-row">
            <div class="control-group">
              <button id="controlPlay" class="control-btn" type="button" aria-label="Play">
                <svg id="controlPlayIcon" viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5.14v13.72c0 .77.83 1.25 1.5.86l10.5-6.86a1 1 0 0 0 0-1.72L9.5 4.28A1 1 0 0 0 8 5.14Z"></path></svg>
              </button>
              <div id="timeLabel" class="time-label">0:00 / 0:00</div>
            </div>
            <div class="control-group right">
              <button id="muteButton" class="control-btn" type="button" aria-label="Mute">
                <svg id="muteIcon" viewBox="0 0 24 24" aria-hidden="true"><path d="M14.82 5.18a.75.75 0 0 1 1.06 0A8.94 8.94 0 0 1 18.5 12a8.94 8.94 0 0 1-2.62 6.82.75.75 0 0 1-1.06-1.06A7.44 7.44 0 0 0 17 12a7.44 7.44 0 0 0-2.18-5.76.75.75 0 0 1 0-1.06ZM4.5 9.5a1 1 0 0 1 1-1H8l4.1-3.28c.66-.53 1.65-.06 1.65.79v11.98c0 .85-.99 1.32-1.65.79L8 15.5H5.5a1 1 0 0 1-1-1v-5Z"></path></svg>
              </button>
              <div id="volumeWrap" class="volume-wrap"><input id="volumeSlider" class="volume-slider" type="range" min="0" max="100" value="${muted ? 0 : 100}" step="1" aria-label="Volume" /></div>
              <button id="fullscreenButton" class="control-btn" type="button" aria-label="Fullscreen">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 3a1 1 0 0 1 0 2H5v2a1 1 0 1 1-2 0V4a1 1 0 0 1 1-1h3Zm14 0a1 1 0 0 1 1 1v3a1 1 0 1 1-2 0V5h-2a1 1 0 1 1 0-2h3ZM4 16a1 1 0 0 1 1 1v2h2a1 1 0 1 1 0 2H4a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1Zm17 0a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-3a1 1 0 1 1 0-2h2v-2a1 1 0 0 1 1-1Z"></path></svg>
              </button>
            </div>
          </div>
        </div>
      </div>
    </main>
    <script>
      const sourceUrl = ${safeSource};
      const streamType = ${safeType};
      const engine = ${safeEngine};
      const playerShell = document.querySelector(".player-shell");
      const video = document.getElementById("player");
      const overlay = document.getElementById("overlay");
      const playButton = document.getElementById("playButton");
      const pulseRing = document.getElementById("pulseRing");
      const controlsShell = document.getElementById("controlsShell");
      const seekbar = document.getElementById("seekbar");
      const controlPlay = document.getElementById("controlPlay");
      const controlPlayIcon = document.getElementById("controlPlayIcon");
      const muteButton = document.getElementById("muteButton");
      const muteIcon = document.getElementById("muteIcon");
      const volumeWrap = document.getElementById("volumeWrap");
      const volumeSlider = document.getElementById("volumeSlider");
      const timeLabel = document.getElementById("timeLabel");
      const livePill = document.getElementById("livePill");
      const fullscreenButton = document.getElementById("fullscreenButton");
      let sourcePrepared = false;
      let hlsInstance = null;
      let dashInstance = null;
      let isSeeking = false;
      let controlsHideTimer = null;
      video.autoplay = ${safeAutoplay};
      video.muted = ${safeMuted};
      video.controls = false;
      function syncFrameRatio() { if (video.videoWidth && video.videoHeight) playerShell.style.setProperty("--frame-ratio", video.videoWidth + " / " + video.videoHeight); }
      function formatTime(seconds) {
        if (!Number.isFinite(seconds) || seconds < 0) return "0:00";
        const whole = Math.floor(seconds), hours = Math.floor(whole / 3600), minutes = Math.floor((whole % 3600) / 60), secs = whole % 60;
        return hours > 0 ? hours + ":" + String(minutes).padStart(2, "0") + ":" + String(secs).padStart(2, "0") : minutes + ":" + String(secs).padStart(2, "0");
      }
      function setRangeProgress(element, value, max) { element.style.setProperty("--value", (max > 0 ? value / max * 100 : 0) + "%"); }
      function updateTimeUi() {
        const isLive = !Number.isFinite(video.duration) || video.duration === Infinity;
        livePill.hidden = !isLive;
        seekbar.disabled = isLive;
        if (isLive) {
          timeLabel.textContent = formatTime(video.currentTime) + " / LIVE";
          setRangeProgress(seekbar, 0, 1);
          return;
        }
        const current = isSeeking ? Number(seekbar.value) / 1000 * (video.duration || 0) : video.currentTime;
        const duration = video.duration || 0;
        timeLabel.textContent = formatTime(current) + " / " + formatTime(duration);
        const progress = duration > 0 ? current / duration * 1000 : 0;
        if (!isSeeking) seekbar.value = String(progress);
        setRangeProgress(seekbar, Number(seekbar.value || 0), 1000);
      }
      function updateVolumeUi() {
        const volumeValue = video.muted ? 0 : Math.round(video.volume * 100);
        volumeSlider.value = String(volumeValue);
        setRangeProgress(volumeSlider, volumeValue, 100);
        muteButton.setAttribute("aria-label", video.muted || video.volume === 0 ? "Unmute" : "Mute");
        muteIcon.innerHTML = video.muted || video.volume === 0
          ? '<path d="M4.5 9.5a1 1 0 0 1 1-1H8l4.1-3.28c.66-.53 1.65-.06 1.65.79v11.98c0 .85-.99 1.32-1.65.79L8 15.5H5.5a1 1 0 0 1-1-1v-5Z"></path><path d="M17.28 7.78a.75.75 0 1 1 1.06-1.06L21.62 10a.75.75 0 0 1 0 1.06l-3.28 3.28a.75.75 0 1 1-1.06-1.06L19.5 11.06l-2.22-2.22Z"></path>'
          : '<path d="M14.82 5.18a.75.75 0 0 1 1.06 0A8.94 8.94 0 0 1 18.5 12a8.94 8.94 0 0 1-2.62 6.82.75.75 0 0 1-1.06-1.06A7.44 7.44 0 0 0 17 12a7.44 7.44 0 0 0-2.18-5.76.75.75 0 0 1 0-1.06ZM4.5 9.5a1 1 0 0 1 1-1H8l4.1-3.28c.66-.53 1.65-.06 1.65.79v11.98c0 .85-.99 1.32-1.65.79L8 15.5H5.5a1 1 0 0 1-1-1v-5Z"></path>';
      }
      function updatePlayUi() {
        const isPlaying = !video.paused && !video.ended;
        controlPlay.setAttribute("aria-label", isPlaying ? "Pause" : "Play");
        controlPlayIcon.innerHTML = isPlaying
          ? '<rect x="6.5" y="5.2" width="4.2" height="13.6" rx="1.2"></rect><rect x="13.3" y="5.2" width="4.2" height="13.6" rx="1.2"></rect>'
          : '<path d="M8 5.14v13.72c0 .77.83 1.25 1.5.86l10.5-6.86a1 1 0 0 0 0-1.72L9.5 4.28A1 1 0 0 0 8 5.14Z"></path>';
      }
      function syncPlayButton() {
        const isPlaying = !video.paused && !video.ended;
        playButton.classList.toggle("is-playing", isPlaying);
        playButton.classList.toggle("is-paused", !isPlaying);
        playButton.setAttribute("aria-label", isPlaying ? "Pause video" : "Play video");
        overlay.classList.toggle("is-playing", isPlaying);
        overlay.classList.toggle("is-paused", !isPlaying);
        updatePlayUi();
      }
      function animateButton() {
        playButton.classList.remove("bump");
        pulseRing.classList.remove("active");
        void playButton.offsetWidth;
        playButton.classList.add("bump");
        pulseRing.classList.add("active");
      }
      function showControls() {
        if (!${safeControls}) return;
        controlsShell.classList.remove("hidden");
        clearTimeout(controlsHideTimer);
        if (!video.paused && !video.ended) controlsHideTimer = setTimeout(() => controlsShell.classList.add("hidden"), 2200);
      }
      function toggleVolumePanel(forceOpen) {
        const nextState = typeof forceOpen === "boolean" ? forceOpen : !volumeWrap.classList.contains("open");
        volumeWrap.classList.toggle("open", nextState);
      }
      function shouldIgnoreShellClick(event) {
        if (controlsShell.contains(event.target)) return true;
        if (event.target === playButton || playButton.contains(event.target)) return true;
        if (event.target.closest("button") || event.target.closest("input")) return true;
        if (${safeControls}) showControls();
        return false;
      }
      function reportError(scope, details) {
        const payload = JSON.stringify({ scope, details, sourceUrl, streamType, page: window.location.href, userAgent: navigator.userAgent, timestamp: new Date().toISOString() });
        if (navigator.sendBeacon) {
          navigator.sendBeacon("/__client-error", payload);
          return;
        }
        fetch("/__client-error", { method: "POST", headers: { "Content-Type": "application/json" }, body: payload, keepalive: true }).catch(() => {});
      }
      function togglePlayback(scope) {
        if (!sourcePrepared && streamType === "hls" && hlsInstance) reportError(scope + "_before_hls_ready", { sourceUrl });
        if (!video.paused && !video.ended) {
          animateButton();
          video.pause();
          syncPlayButton();
          return;
        }
        tryPlay(scope + "_failed");
      }
      function tryPlay(scope) {
        const playPromise = video.play();
        if (!playPromise || typeof playPromise.then !== "function") {
          animateButton();
          syncPlayButton();
          return;
        }
        playPromise.then(() => { animateButton(); syncPlayButton(); }).catch((error) => {
          syncPlayButton();
          reportError(scope, { message: error && error.message ? error.message : String(error), name: error && error.name ? error.name : null });
        });
      }
      function failSilently(scope, details) {
        video.hidden = true;
        overlay.hidden = true;
        reportError(scope, details);
      }
      function setBufferingState(isBuffering) { playButton.classList.toggle("is-buffering", isBuffering); }
      function loadHls() {
        if ((engine === "hlsjs" || engine === "auto") && window.Hls && window.Hls.isSupported()) {
          hlsInstance = new window.Hls({ enableWorker: true, lowLatencyMode: true });
          hlsInstance.loadSource(sourceUrl);
          hlsInstance.attachMedia(video);
          hlsInstance.on(window.Hls.Events.MANIFEST_PARSED, () => { sourcePrepared = true; updateTimeUi(); });
          hlsInstance.on(window.Hls.Events.ERROR, (_, data) => {
            reportError("hlsjs_error", data);
            if (data && data.fatal) {
              video.hidden = true;
              overlay.hidden = true;
            }
          });
          hlsInstance.on(window.Hls.Events.BUFFER_STALLED, () => setBufferingState(true));
          hlsInstance.on(window.Hls.Events.FRAG_BUFFERED, () => setBufferingState(false));
          video.addEventListener("error", () => reportError("hlsjs_media_error", { code: video.error ? video.error.code : null }));
          return;
        }
        if ((engine === "native" || engine === "auto") && video.canPlayType("application/vnd.apple.mpegurl")) {
          video.src = sourceUrl;
          video.addEventListener("loadedmetadata", () => { sourcePrepared = true; }, { once: true });
          video.addEventListener("error", () => failSilently("hls_native_playback_error", { code: video.error ? video.error.code : null }));
          return;
        }
        failSilently("hls_not_supported", { reason: "Browser ini tidak mendukung HLS lewat engine yang dipilih.", engine });
      }
      function loadDash() {
        if (window.dashjs) {
          dashInstance = window.dashjs.MediaPlayer().create();
          dashInstance.initialize(video, sourceUrl, ${safeAutoplay});
          sourcePrepared = true;
          dashInstance.on("error", (event) => failSilently("dash_error", event));
          dashInstance.on("bufferStalled", () => setBufferingState(true));
          dashInstance.on("playbackPlaying", () => setBufferingState(false));
          return;
        }
        failSilently("dash_library_load_failed", { reason: "Library DASH tidak berhasil dimuat." });
      }
      if (streamType === "hls") loadHls();
      else if (streamType === "dash") loadDash();
      else failSilently("unknown_stream_type", { reason: "Tipe stream tidak dikenali." });
      playButton.addEventListener("click", () => togglePlayback("manual_play"));
      controlPlay.addEventListener("click", () => togglePlayback("control_play"));
      muteButton.addEventListener("click", () => {
        const panelOpen = volumeWrap.classList.contains("open");
        if (!panelOpen) { toggleVolumePanel(true); showControls(); return; }
        video.muted = !video.muted;
        updateVolumeUi();
        showControls();
      });
      volumeSlider.addEventListener("input", () => {
        const volumeValue = Number(volumeSlider.value) / 100;
        video.volume = volumeValue;
        video.muted = volumeValue === 0;
        updateVolumeUi();
        toggleVolumePanel(true);
        showControls();
      });
      seekbar.addEventListener("input", () => { isSeeking = true; updateTimeUi(); showControls(); });
      seekbar.addEventListener("change", () => {
        if (Number.isFinite(video.duration) && video.duration > 0) video.currentTime = Number(seekbar.value) / 1000 * video.duration;
        isSeeking = false;
        updateTimeUi();
      });
      fullscreenButton.addEventListener("click", async () => {
        try {
          if (document.fullscreenElement) await document.exitFullscreen();
          else await playerShell.requestFullscreen();
        } catch (error) {
          reportError("fullscreen_failed", { message: error && error.message ? error.message : String(error) });
        }
      });
      playerShell.addEventListener("click", (event) => { if (!shouldIgnoreShellClick(event)) togglePlayback("shell_click"); });
      video.addEventListener("click", (event) => { if (!shouldIgnoreShellClick(event)) togglePlayback("video_click"); });
      pulseRing.addEventListener("animationend", () => pulseRing.classList.remove("active"));
      playerShell.addEventListener("pointermove", () => { overlay.classList.add("is-hovered"); showControls(); });
      playerShell.addEventListener("pointerleave", () => { overlay.classList.remove("is-hovered"); toggleVolumePanel(false); if (!video.paused && !video.ended && ${safeControls}) controlsShell.classList.add("hidden"); });
      video.addEventListener("play", syncPlayButton);
      video.addEventListener("pause", syncPlayButton);
      video.addEventListener("ended", syncPlayButton);
      video.addEventListener("timeupdate", updateTimeUi);
      video.addEventListener("loadedmetadata", syncFrameRatio);
      video.addEventListener("loadedmetadata", updateTimeUi);
      video.addEventListener("durationchange", updateTimeUi);
      video.addEventListener("volumechange", updateVolumeUi);
      video.addEventListener("waiting", () => setBufferingState(true));
      video.addEventListener("playing", () => { setBufferingState(false); showControls(); });
      video.addEventListener("canplay", () => setBufferingState(false));
      video.addEventListener("seeking", () => setBufferingState(true));
      video.addEventListener("seeked", () => setBufferingState(false));
      document.addEventListener("fullscreenchange", () => showControls());
      syncPlayButton();
      updateVolumeUi();
      updateTimeUi();
      showControls();
      window.addEventListener("error", (event) => failSilently("window_error", { message: event.message, filename: event.filename, lineno: event.lineno, colno: event.colno }));
      window.addEventListener("unhandledrejection", (event) => failSilently("unhandled_rejection", { reason: String(event.reason) }));
    </script>
  </body>
</html>`;
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function emptyResponse(status = 204) {
  return new Response(null, {
    status,
    headers: {
      ...corsHeaders,
      "Cache-Control": "no-store",
    },
  });
}

async function handleProxy(request, requestUrl, publicOrigin, secret) {
  const token = requestUrl.searchParams.get("token");
  const payload = await decodeToken(token, secret);
  if (!payload || typeof payload.proxyUrl !== "string") {
    logError("proxy_invalid_token", { path: requestUrl.pathname, query: requestUrl.search });
    return emptyResponse(400);
  }

  const validation = validateSource(payload.proxyUrl);
  if (validation.error) {
    logError("proxy_validation_failed", { error: validation.error, proxyUrl: payload.proxyUrl });
    return emptyResponse(400);
  }

  const upstreamHeaders = new Headers();
  const preset = getSourcePreset(validation.sourceUrl);
  const customHeaders = parseHeaderLines(payload.headers || preset.headers || "");
  Object.entries(customHeaders).forEach(([name, value]) => upstreamHeaders.set(name, value));

  if (!upstreamHeaders.has("user-agent")) {
    upstreamHeaders.set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36");
  }
  if (!upstreamHeaders.has("accept")) {
    upstreamHeaders.set("accept", request.headers.get("accept") || "*/*");
  }
  if (request.headers.get("range")) upstreamHeaders.set("range", request.headers.get("range"));
  if (request.headers.get("if-none-match")) upstreamHeaders.set("if-none-match", request.headers.get("if-none-match"));
  if (request.headers.get("if-modified-since")) upstreamHeaders.set("if-modified-since", request.headers.get("if-modified-since"));

  const referer = payload.referer || preset.referer || "";
  const cookie = payload.cookie || preset.cookie || "";
  if (referer) upstreamHeaders.set("referer", referer);
  if (cookie) upstreamHeaders.set("cookie", cookie);

  const upstreamResponse = await fetch(validation.sourceUrl, {
    method: request.method,
    headers: upstreamHeaders,
    redirect: "follow",
  });

  const contentType = upstreamResponse.headers.get("content-type") || "application/octet-stream";
  const responseHeaders = new Headers(corsHeaders);
  responseHeaders.set("Cache-Control", "no-store");
  responseHeaders.set("Content-Type", contentType);
  [
    "accept-ranges",
    "cache-control",
    "content-length",
    "content-range",
    "etag",
    "expires",
    "last-modified",
  ].forEach((name) => {
    const value = upstreamResponse.headers.get(name);
    if (value) responseHeaders.set(name, value);
  });

  const bodyBuffer = await upstreamResponse.arrayBuffer();
  const bodyText = new TextDecoder().decode(bodyBuffer);
  if (!upstreamResponse.ok) {
    logError("proxy_upstream_failed", {
      status: upstreamResponse.status,
      proxyUrl: validation.sourceUrl,
      referer,
      cookie,
      headers: {
        contentType,
        contentLength: upstreamResponse.headers.get("content-length"),
        accessControlAllowOrigin: upstreamResponse.headers.get("access-control-allow-origin"),
        server: upstreamResponse.headers.get("server"),
      },
      requestHeaders: Object.fromEntries(upstreamHeaders.entries()),
      preview: bodyText.slice(0, 500),
    });
  }

  const proxyOptions = {
    referer,
    cookie,
    headers: payload.headers || preset.headers || "",
  };

  if (request.method === "HEAD") {
    return new Response(null, { status: upstreamResponse.status, headers: responseHeaders });
  }

  if (validation.sourceUrl.toLowerCase().endsWith(".m3u8") || playlistMimeTypes.some((mime) => contentType.toLowerCase().includes(mime))) {
    const rewritten = await rewriteHlsManifest(bodyText, upstreamResponse.url, publicOrigin, proxyOptions, secret);
    responseHeaders.set("Content-Type", contentType || "application/vnd.apple.mpegurl");
    responseHeaders.delete("content-length");
    return new Response(rewritten, { status: upstreamResponse.status, headers: responseHeaders });
  }

  if (validation.sourceUrl.toLowerCase().endsWith(".mpd") || dashMimeTypes.some((mime) => contentType.toLowerCase().includes(mime))) {
    const rewritten = await rewriteDashManifest(bodyText, upstreamResponse.url, publicOrigin, proxyOptions, secret);
    responseHeaders.set("Content-Type", contentType || "application/dash+xml");
    responseHeaders.delete("content-length");
    return new Response(rewritten, { status: upstreamResponse.status, headers: responseHeaders });
  }

  return new Response(bodyBuffer, { status: upstreamResponse.status, headers: responseHeaders });
}

function resolveEmbedParams(requestUrl) {
  return {
    sourceUrl: requestUrl.searchParams.get("src"),
    requestedType: requestUrl.searchParams.get("type"),
    autoplay: requestUrl.searchParams.get("autoplay"),
    muted: requestUrl.searchParams.get("muted"),
    controls: requestUrl.searchParams.get("controls"),
    title: requestUrl.searchParams.get("title"),
    engine: requestUrl.searchParams.get("engine"),
    referer: requestUrl.searchParams.get("referer"),
    cookie: requestUrl.searchParams.get("cookie"),
    headers: requestUrl.searchParams.get("headers"),
  };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return emptyResponse(204);

    const requestUrl = new URL(request.url);
    const publicOrigin = getPublicOrigin(request, requestUrl);
    const secret = env.EMBED_SECRET || EMBED_SECRET;

    try {
      if (requestUrl.pathname === "/__client-error" && request.method === "POST") {
        try {
          const payload = await request.json();
          logError("client_error", payload);
        } catch {
          logError("client_error_parse_failed", {});
        }
        return emptyResponse(204);
      }

      if (!["GET", "HEAD"].includes(request.method)) {
        logError("invalid_method", { method: request.method, path: requestUrl.pathname });
        return emptyResponse(405);
      }

      if (requestUrl.pathname === "/") {
        return jsonResponse(buildLandingPage(publicOrigin, env.EMBED_SECRET || ""));
      }

      if (requestUrl.pathname === "/favicon.ico") {
        return emptyResponse(204);
      }

      if (requestUrl.pathname === "/health") {
        return jsonResponse({
          status: "ok",
          timestamp: new Date().toISOString(),
        });
      }

      if (requestUrl.pathname === "/proxy") {
        return handleProxy(request, requestUrl, publicOrigin, secret);
      }

      if (requestUrl.pathname === "/sign") {
        const resolved = resolveEmbedParams(requestUrl);
        const validation = validateSource(resolved.sourceUrl);
        if (validation.error) {
          logError("sign_validation_failed", { error: validation.error, query: requestUrl.search });
          return emptyResponse(400);
        }

        const requestedType = (resolved.requestedType || "auto").toLowerCase();
        const inferredType = guessStreamType(validation.sourceUrl);
        const streamType = requestedType === "auto" ? inferredType : requestedType;
        if (!["hls", "dash"].includes(streamType)) {
          logError("sign_invalid_stream_type", { requestedType, inferredType, sourceUrl: validation.sourceUrl });
          return emptyResponse(400);
        }

        const engine = (resolved.engine || "auto").toLowerCase();
        if (!["auto", "native", "hlsjs"].includes(engine)) {
          logError("sign_invalid_engine", { engine, sourceUrl: validation.sourceUrl });
          return emptyResponse(400);
        }

        const proxyOptions = createProxyOptions(validation.sourceUrl, resolved);
        const token = await createToken({
          src: validation.sourceUrl,
          type: streamType,
          autoplay: parseBoolean(resolved.autoplay),
          muted: parseBoolean(resolved.muted),
          controls: parseBoolean(resolved.controls, true),
          title: resolved.title || "",
          engine,
          referer: proxyOptions.referer,
          cookie: proxyOptions.cookie,
          headers: proxyOptions.headers,
        }, secret);

        return jsonResponse({
          token,
          embedUrl: `${publicOrigin}/embed?token=${token}`,
        });
      }

      if (requestUrl.pathname === "/embed") {
        let resolved = resolveEmbedParams(requestUrl);
        const token = requestUrl.searchParams.get("token");
        if (token) {
          const payload = await decodeToken(token, secret);
          if (!payload || typeof payload.src !== "string") {
            logError("embed_token_invalid", { query: requestUrl.search });
            return emptyResponse(400);
          }
          resolved = {
            sourceUrl: payload.src,
            requestedType: payload.type,
            autoplay: payload.autoplay,
            muted: payload.muted,
            controls: payload.controls,
            title: payload.title,
            engine: payload.engine,
            referer: payload.referer,
            cookie: payload.cookie,
            headers: payload.headers,
          };
        }

        const validation = validateSource(resolved.sourceUrl);
        if (validation.error) {
          logError("embed_validation_failed", { error: validation.error, query: requestUrl.search });
          return emptyResponse(400);
        }

        const requestedType = (resolved.requestedType || "auto").toLowerCase();
        const inferredType = guessStreamType(validation.sourceUrl);
        const streamType = requestedType === "auto" ? inferredType : requestedType;
        if (!["hls", "dash"].includes(streamType)) {
          logError("embed_invalid_stream_type", { requestedType, inferredType, sourceUrl: validation.sourceUrl });
          return emptyResponse(400);
        }

        const engine = (resolved.engine || "auto").toLowerCase();
        if (!["auto", "native", "hlsjs"].includes(engine)) {
          logError("embed_invalid_engine", { engine, sourceUrl: validation.sourceUrl });
          return emptyResponse(400);
        }

        const playbackUrl = await getProxyUrl(publicOrigin, validation.sourceUrl, createProxyOptions(validation.sourceUrl, resolved), secret);
        return htmlResponse(buildEmbedHtml({
          sourceUrl: validation.sourceUrl,
          playbackUrl,
          streamType,
          autoplay: parseBoolean(resolved.autoplay),
          muted: parseBoolean(resolved.muted),
          controls: parseBoolean(resolved.controls, true),
          title: resolved.title,
          engine,
        }));
      }

      logError("route_not_found", { method: request.method, path: requestUrl.pathname });
      return emptyResponse(404);
    } catch (error) {
      logError("request_handler_failed", error && error.stack ? error.stack : String(error));
      return emptyResponse(500);
    }
  },
};
