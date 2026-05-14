const http = require("node:http");
const crypto = require("node:crypto");
const { URL } = require("node:url");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const PROBE_COOLDOWN_MS = 30_000;
const FETCH_TIMEOUT_MS = 15_000;
const EMBED_SECRET = process.env.EMBED_SECRET || "bangbot2026";
const probeCache = new Map();

function logError(scope, details) {
  console.error(`[${new Date().toISOString()}] ${scope}`, details);
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload, null, 2));
}

function sendHtml(response, statusCode, html) {
  response.writeHead(statusCode, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(html);
}

function sendEmpty(response, statusCode) {
  response.writeHead(statusCode, {
    "Cache-Control": "no-store",
  });
  response.end();
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
  if (value == null) return defaultValue;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function getHeaderValue(header) {
  if (Array.isArray(header)) {
    return header[0];
  }
  return header || "";
}

function getPublicOrigin(request) {
  const forwardedProto = getHeaderValue(request.headers["x-forwarded-proto"]).split(",")[0].trim();
  const forwardedHost = getHeaderValue(request.headers["x-forwarded-host"]).split(",")[0].trim();
  const host = forwardedHost || getHeaderValue(request.headers.host) || "localhost";
  const proto = forwardedProto || "http";
  return `${proto}://${host}`;
}

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function base64UrlDecode(value) {
  const normalized = String(value)
    .replaceAll("-", "+")
    .replaceAll("_", "/");
  const padding = "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
  return Buffer.from(normalized + padding, "base64");
}

function getSecretKey() {
  return crypto.createHash("sha256").update(EMBED_SECRET).digest();
}

function createEmbedToken(payload) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getSecretKey(), iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(payload), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return [iv, tag, encrypted].map(base64UrlEncode).join(".");
}

function decodeEmbedToken(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) {
    return null;
  }

  try {
    const [iv, tag, encrypted] = parts.map(base64UrlDecode);
    const decipher = crypto.createDecipheriv("aes-256-gcm", getSecretKey(), iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);
    return JSON.parse(decrypted.toString("utf8"));
  } catch {
    return null;
  }
}

function createProxyToken(url) {
  return createEmbedToken({ proxyUrl: url });
}

function getProxyUrl(origin, url) {
  return `${origin}/proxy?token=${encodeURIComponent(createProxyToken(url))}`;
}

function summarizeHeaders(headers) {
  return {
    contentType: headers.get("content-type"),
    contentLength: headers.get("content-length"),
    accessControlAllowOrigin: headers.get("access-control-allow-origin"),
    accessControlAllowCredentials: headers.get("access-control-allow-credentials"),
    cacheControl: headers.get("cache-control"),
    server: headers.get("server"),
  };
}

function summarizeProbeOutcome(sourceUrl, streamType, result) {
  if (streamType === "hls") {
    if (!result.manifest?.ok) {
      return {
        severity: "error",
        summary: "Manifest HLS gagal diambil.",
        hints: [
          `Manifest status ${result.manifest?.status ?? "unknown"}`,
          "Periksa URL manifest, token, referer policy, atau origin restriction.",
        ],
      };
    }

    if (result.segment && !result.segment.ok) {
      return {
        severity: "error",
        summary: "Manifest HLS terbuka, tetapi segment media gagal diambil.",
        hints: [
          `Segment status ${result.segment.status} pada ${result.segment.url}`,
          "Ini biasanya berarti playlist menunjuk ke segment yang sudah hilang, path salah, token segment berbeda, atau hotlink protection aktif di level segment.",
        ],
      };
    }

    if (!result.segment && !result.variant) {
      return {
        severity: "warn",
        summary: "Manifest HLS terbuka, tetapi belum ditemukan varian atau segment yang bisa diuji.",
        hints: [
          "Periksa format manifest. Bisa jadi playlist tidak standar atau kosong saat diprobe.",
        ],
      };
    }

    return {
      severity: "info",
      summary: "Probe HLS terlihat sehat.",
      hints: [
        `Manifest ${result.manifest.status}`,
        result.segment ? `Segment ${result.segment.status}` : "Segment belum diuji",
      ],
    };
  }

  if (streamType === "dash") {
    if (!result.manifest?.ok) {
      return {
        severity: "error",
        summary: "Manifest DASH gagal diambil.",
        hints: [
          `Manifest status ${result.manifest?.status ?? "unknown"}`,
          "Periksa URL MPD, token, referer policy, atau origin restriction.",
        ],
      };
    }

    return {
      severity: "info",
      summary: "Probe DASH manifest terlihat sehat.",
      hints: [`Manifest ${result.manifest.status}`],
    };
  }

  return {
    severity: "info",
    summary: `Probe ${streamType} selesai.`,
    hints: [sourceUrl],
  };
}

function logProbeResult(sourceUrl, streamType, result) {
  const outcome = summarizeProbeOutcome(sourceUrl, streamType, result);
  const scope = `stream_probe_${streamType}_${outcome.severity}`;

  logError(scope, {
    sourceUrl,
    summary: outcome.summary,
    hints: outcome.hints,
    details: result,
  });
}

async function fetchWithTimeout(resource, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    return await fetch(resource, {
      ...options,
      signal: controller.signal,
      headers: {
        "user-agent": "embedstreaming-probe/1.0",
        ...(options.headers || {}),
      },
      redirect: "follow",
    });
  } finally {
    clearTimeout(timeout);
  }
}

function parseHlsManifest(manifestText, baseUrl) {
  const lines = manifestText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const variants = [];
  const segments = [];
  let pendingVariant = false;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];

    if (line.startsWith("#EXT-X-STREAM-INF")) {
      pendingVariant = true;
      continue;
    }

    if (!line.startsWith("#")) {
      if (pendingVariant) {
        variants.push(new URL(line, baseUrl).toString());
        pendingVariant = false;
      } else {
        segments.push(new URL(line, baseUrl).toString());
      }
    }
  }

  return { variants, segments };
}

async function probeHlsStream(sourceUrl) {
  const result = {
    sourceUrl,
    manifest: null,
    variant: null,
    segment: null,
  };

  const manifestResponse = await fetchWithTimeout(sourceUrl);
  const manifestBody = await manifestResponse.text();

  result.manifest = {
    ok: manifestResponse.ok,
    status: manifestResponse.status,
    url: manifestResponse.url,
    headers: summarizeHeaders(manifestResponse.headers),
    preview: manifestBody.slice(0, 400),
  };

  if (!manifestResponse.ok) {
    return result;
  }

  const parsedManifest = parseHlsManifest(manifestBody, manifestResponse.url);
  const variantUrl = parsedManifest.variants[0] || null;
  const segmentUrl = parsedManifest.segments[0] || null;

  if (variantUrl) {
    const variantResponse = await fetchWithTimeout(variantUrl);
    const variantBody = await variantResponse.text();
    result.variant = {
      ok: variantResponse.ok,
      status: variantResponse.status,
      url: variantResponse.url,
      headers: summarizeHeaders(variantResponse.headers),
      preview: variantBody.slice(0, 400),
    };

    if (variantResponse.ok) {
      const parsedVariant = parseHlsManifest(variantBody, variantResponse.url);
      if (!segmentUrl && parsedVariant.segments[0]) {
        result.segment = await probeMediaSegment(parsedVariant.segments[0]);
      }
    }
  }

  if (!result.segment && segmentUrl) {
    result.segment = await probeMediaSegment(segmentUrl);
  }

  return result;
}

async function probeMediaSegment(segmentUrl) {
  const response = await fetchWithTimeout(segmentUrl, {
    method: "GET",
    headers: {
      range: "bytes=0-0",
    },
  });

  return {
    ok: response.ok,
    status: response.status,
    url: response.url,
    headers: summarizeHeaders(response.headers),
  };
}

async function probeDashStream(sourceUrl) {
  const response = await fetchWithTimeout(sourceUrl);
  const body = await response.text();

  return {
    sourceUrl,
    manifest: {
      ok: response.ok,
      status: response.status,
      url: response.url,
      headers: summarizeHeaders(response.headers),
      preview: body.slice(0, 400),
    },
  };
}

async function runStreamProbe(sourceUrl, streamType) {
  const cacheKey = `${streamType}:${sourceUrl}`;
  const previousProbeAt = probeCache.get(cacheKey);

  if (previousProbeAt && Date.now() - previousProbeAt < PROBE_COOLDOWN_MS) {
    return;
  }

  probeCache.set(cacheKey, Date.now());

  try {
    if (streamType === "hls") {
      const result = await probeHlsStream(sourceUrl);
      logProbeResult(sourceUrl, streamType, result);
      return;
    }

    if (streamType === "dash") {
      const result = await probeDashStream(sourceUrl);
      logProbeResult(sourceUrl, streamType, result);
    }
  } catch (error) {
    logError("stream_probe_failed", {
      sourceUrl,
      streamType,
      error: error && error.stack ? error.stack : String(error),
    });
  }
}

function guessStreamType(sourceUrl) {
  const pathname = new URL(sourceUrl).pathname.toLowerCase();

  if (pathname.endsWith(".m3u8")) return "hls";
  if (pathname.endsWith(".mpd")) return "dash";
  return "unknown";
}

function validateSource(rawSource) {
  if (!rawSource) {
    return { error: "Parameter 'src' wajib diisi." };
  }

  if (rawSource.includes("/http://") || rawSource.includes("/https://")) {
    return { error: "Parameter 'src' terlihat malformed atau terduplikasi." };
  }

  let parsed;
  try {
    parsed = new URL(rawSource);
  } catch {
    return { error: "Parameter 'src' harus berupa URL yang valid." };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { error: "Hanya URL http/https yang didukung." };
  }

  return { sourceUrl: parsed.toString() };
}

function rewriteHlsManifest(manifestText, baseUrl, origin) {
  const lines = manifestText.split(/\r?\n/);

  return lines.map((line) => {
    const trimmed = line.trim();

    if (!trimmed) {
      return line;
    }

    if (trimmed.startsWith("#")) {
      return line.replace(/URI="([^"]+)"/g, (_, uri) => {
        const absoluteUrl = new URL(uri, baseUrl).toString();
        return `URI="${getProxyUrl(origin, absoluteUrl)}"`;
      });
    }

    return getProxyUrl(origin, new URL(trimmed, baseUrl).toString());
  }).join("\n");
}

function rewriteDashManifest(mpdText, baseUrl, origin) {
  return mpdText
    .replace(/<BaseURL>([^<]+)<\/BaseURL>/g, (_, url) => {
      const absoluteUrl = new URL(url.trim(), baseUrl).toString();
      return `<BaseURL>${getProxyUrl(origin, absoluteUrl)}</BaseURL>`;
    })
    .replace(/\b(initialization|media|sourceURL|mediaRange|indexRange)="([^"]+)"/g, (full, attr, value) => {
      if (!value || value.startsWith("$") || attr === "mediaRange" || attr === "indexRange") {
        return full;
      }

      const absoluteUrl = new URL(value.trim(), baseUrl).toString();
      return `${attr}="${getProxyUrl(origin, absoluteUrl)}"`;
    })
    .replace(/<(Initialization|SegmentURL)\b([^>]*?)\bsourceURL="([^"]+)"/g, (_, tag, rest, value) => {
      const absoluteUrl = new URL(value.trim(), baseUrl).toString();
      return `<${tag}${rest}sourceURL="${getProxyUrl(origin, absoluteUrl)}"`;
    });
}

async function readResponseBody(response) {
  const arrayBuffer = await response.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

function resolveEmbedParams(requestUrl) {
  const token = requestUrl.searchParams.get("token");
  if (!token) {
    return {
      sourceUrl: requestUrl.searchParams.get("src"),
      requestedType: requestUrl.searchParams.get("type"),
      autoplay: requestUrl.searchParams.get("autoplay"),
      muted: requestUrl.searchParams.get("muted"),
      controls: requestUrl.searchParams.get("controls"),
      title: requestUrl.searchParams.get("title"),
      engine: requestUrl.searchParams.get("engine"),
      usedToken: false,
    };
  }

  const payload = decodeEmbedToken(token);
  if (!payload || typeof payload !== "object") {
    return { error: "Token embed tidak valid." };
  }

  return {
    sourceUrl: payload.src,
    requestedType: payload.type,
    autoplay: payload.autoplay,
    muted: payload.muted,
    controls: payload.controls,
    title: payload.title,
    engine: payload.engine,
    usedToken: true,
  };
}

function buildEmbedTokenPayload(params) {
  return {
    src: params.sourceUrl,
    type: params.streamType,
    autoplay: Boolean(params.autoplay),
    muted: Boolean(params.muted),
    controls: Boolean(params.controls),
    title: params.title || "",
    engine: params.engine || "auto",
  };
}

function buildLandingPage(requestUrl) {
  const hlsSource = "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8";
  const dashSource = "https://dash.akamaized.net/envivio/EnvivioDash3/manifest.mpd";
  const exampleHls = `${requestUrl.origin}/embed?src=${encodeURIComponent(hlsSource)}`;
  const exampleDash = `${requestUrl.origin}/embed?src=${encodeURIComponent(dashSource)}`;
  const exampleHlsToken = createEmbedToken({
    src: hlsSource,
    type: "hls",
    autoplay: false,
    muted: false,
    controls: true,
    title: "BangBot Player",
    engine: "auto",
  });

  return {
    name: "embedstreaming",
    status: "ok",
    endpoints: {
      health: "/health",
      embed: "/embed?src=<stream-url>&type=<auto|hls|dash>",
      sign: "/sign?src=<stream-url>&type=<auto|hls|dash>",
    },
    examples: {
      hls: exampleHls,
      dash: exampleDash,
      tokenizedHls: `${requestUrl.origin}/embed?token=${exampleHlsToken}`,
    },
    notes: [
      "Endpoint /embed mengembalikan halaman HTML player yang siap di-iframe.",
      "Endpoint /sign mengembalikan URL embed dengan token terenkripsi.",
      "Jika parameter type tidak diisi, server akan mencoba menebak dari ekstensi file.",
      "Stream origin tetap harus mengizinkan playback dari browser pengguna.",
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
  const safeStreamLabel = escapeHtml(streamType.toUpperCase());

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
        --text-soft: rgba(226, 232, 240, 0.72);
        --glass: rgba(15, 23, 42, 0.48);
        --glass-border: rgba(255, 255, 255, 0.14);
        --accent: #f8fafc;
        --accent-dark: #0f172a;
      }

      * {
        box-sizing: border-box;
      }

      html,
      body {
        margin: 0;
        width: 100%;
        height: 100%;
        overflow: hidden;
        background: #020617;
        color: var(--text-main);
      }

      body {
        display: grid;
        place-items: center;
        padding: 18px;
      }

      .player-shell {
        position: relative;
        width: min(100%, 960px);
        aspect-ratio: var(--frame-ratio, 16 / 9);
        max-height: calc(100vh - 36px);
        display: grid;
        place-items: center;
        isolation: isolate;
        border-radius: 28px;
        overflow: hidden;
        background: #000;
        box-shadow:
          0 24px 80px rgba(0, 0, 0, 0.45),
          0 0 0 1px rgba(255, 255, 255, 0.06);
      }

      video {
        width: 100%;
        height: 100%;
        background: #000;
        object-fit: contain;
        object-position: center center;
      }

      .overlay {
        position: absolute;
        inset: 0;
        display: block;
        background:
          linear-gradient(180deg, rgba(2, 6, 23, 0.28) 0%, rgba(2, 6, 23, 0.08) 24%, rgba(2, 6, 23, 0.42) 100%);
        pointer-events: none;
        transition: background 220ms ease;
      }

      .brand-corner {
        position: absolute;
        top: 14px;
        left: 14px;
        padding: 9px 13px;
        border: 1px solid var(--glass-border);
        border-radius: 999px;
        background: rgba(15, 23, 42, 0.62);
        backdrop-filter: blur(12px);
        color: var(--text-main);
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        box-shadow: 0 12px 30px rgba(2, 6, 23, 0.26);
      }

      .live-corner {
        position: absolute;
        top: 14px;
        right: 14px;
        z-index: 3;
        pointer-events: none;
      }

      .center-play {
        position: absolute;
        inset: 0;
        display: grid;
        place-items: center;
        pointer-events: none;
      }

      .center-stack {
        display: grid;
        justify-items: center;
        gap: 16px;
        pointer-events: auto;
      }

      .play-button {
        appearance: none;
        border: 0;
        width: 84px;
        height: 84px;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.92);
        color: var(--accent-dark);
        cursor: pointer;
        box-shadow:
          0 18px 45px rgba(2, 6, 23, 0.38),
          0 0 0 14px rgba(255, 255, 255, 0.08);
        transition: transform 180ms ease, box-shadow 180ms ease, background 180ms ease, opacity 180ms ease;
        pointer-events: auto;
      }

      .play-button:hover {
        transform: scale(1.04);
        box-shadow:
          0 22px 54px rgba(2, 6, 23, 0.45),
          0 0 0 18px rgba(255, 255, 255, 0.1);
      }

      .play-button:active {
        transform: scale(0.98);
      }

      .play-button svg {
        width: 34px;
        height: 34px;
        display: block;
        margin: 0 auto;
        overflow: visible;
      }

      .play-spinner {
        position: absolute;
        inset: 50% auto auto 50%;
        width: 34px;
        height: 34px;
        margin: -17px 0 0 -17px;
        border-radius: 50%;
        border: 3px solid rgba(15, 23, 42, 0.18);
        border-top-color: rgba(15, 23, 42, 0.92);
        opacity: 0;
        transform: scale(0.72);
        transition: opacity 180ms ease, transform 180ms ease;
        animation: spin 900ms linear infinite;
        pointer-events: none;
      }

      .play-icon-play,
      .play-icon-pause-left,
      .play-icon-pause-right {
        transform-box: fill-box;
        transform-origin: center;
        transition: transform 220ms ease, opacity 220ms ease;
      }

      .play-icon-play {
        transform: scale(1) translateX(0);
        opacity: 1;
      }

      .play-icon-pause-left,
      .play-icon-pause-right {
        opacity: 0;
      }

      .play-icon-pause-left {
        transform: translateX(-3px) scaleY(0.7);
      }

      .play-icon-pause-right {
        transform: translateX(3px) scaleY(0.7);
      }

      .play-button.is-playing .play-icon-play {
        transform: scale(0.55);
        opacity: 0;
      }

      .play-button.is-playing .play-icon-pause-left,
      .play-button.is-playing .play-icon-pause-right {
        opacity: 1;
        transform: translateX(0) scaleY(1);
      }

      .play-button.is-buffering .play-icon-play,
      .play-button.is-buffering .play-icon-pause-left,
      .play-button.is-buffering .play-icon-pause-right {
        opacity: 0;
        transform: scale(0.5);
      }

      .play-button.is-buffering .play-spinner {
        opacity: 1;
        transform: scale(1);
      }

      .play-button.is-paused {
        opacity: 0.96;
      }

      .play-button.bump {
        animation: button-bump 280ms ease;
      }

      .pulse-ring {
        position: absolute;
        width: 84px;
        height: 84px;
        border-radius: 999px;
        border: 1px solid rgba(255, 255, 255, 0.32);
        background: rgba(255, 255, 255, 0.08);
        opacity: 0;
        transform: scale(0.88);
        pointer-events: none;
      }

      .pulse-ring.active {
        animation: pulse-ring 420ms ease-out;
      }

      .controls-shell {
        position: absolute;
        left: 0;
        right: 0;
        bottom: 0;
        padding: 32px 16px 14px;
        background: linear-gradient(180deg, rgba(2, 6, 23, 0) 0%, rgba(2, 6, 23, 0.82) 72%);
        pointer-events: none;
        opacity: 1;
        transform: translateY(0);
        transition: opacity 220ms ease, transform 220ms ease;
      }

      .controls-shell.hidden {
        opacity: 0;
        transform: translateY(12px);
      }

      .seek-wrap,
      .control-row {
        pointer-events: auto;
      }

      .seek-wrap {
        display: grid;
        margin-bottom: 14px;
      }

      .seekbar,
      .volume-slider {
        -webkit-appearance: none;
        appearance: none;
        width: 100%;
        height: 6px;
        border-radius: 999px;
        outline: none;
        background: linear-gradient(90deg, rgba(248, 250, 252, 0.96) var(--value, 0%), rgba(255, 255, 255, 0.22) var(--value, 0%));
        cursor: pointer;
      }

      .seekbar::-webkit-slider-thumb,
      .volume-slider::-webkit-slider-thumb {
        -webkit-appearance: none;
        appearance: none;
        width: 14px;
        height: 14px;
        border-radius: 50%;
        border: 0;
        background: #ffffff;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.28);
      }

      .seekbar::-moz-range-thumb,
      .volume-slider::-moz-range-thumb {
        width: 14px;
        height: 14px;
        border: 0;
        border-radius: 50%;
        background: #ffffff;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.28);
      }

      .control-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 14px;
        min-width: 0;
      }

      .control-group {
        display: flex;
        align-items: center;
        gap: 10px;
        min-width: 0;
      }

      .control-group.right {
        margin-left: auto;
        justify-content: flex-end;
      }

      .control-btn {
        display: inline-grid;
        place-items: center;
        width: 40px;
        height: 40px;
        padding: 0;
        border: 0;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.08);
        color: #f8fafc;
        cursor: pointer;
        transition: transform 160ms ease, background 160ms ease;
      }

      .control-btn:hover {
        transform: translateY(-1px);
        background: rgba(255, 255, 255, 0.14);
      }

      .control-btn svg {
        width: 18px;
        height: 18px;
        fill: currentColor;
      }

      .time-label {
        color: rgba(248, 250, 252, 0.94);
        font-size: 13px;
        font-variant-numeric: tabular-nums;
        white-space: nowrap;
        text-align: right;
      }

      .volume-wrap {
        display: flex;
        align-items: center;
        gap: 10px;
        width: 0;
        overflow: hidden;
        opacity: 0;
        transform: translateX(-6px);
        transition: width 180ms ease, opacity 180ms ease, transform 180ms ease;
      }

      .volume-wrap.open {
        width: 132px;
        opacity: 1;
        transform: translateX(0);
      }

      .live-pill {
        display: inline-flex;
        align-items: center;
        gap: 7px;
        min-width: 62px;
        padding: 0 10px;
        height: 30px;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.08);
        color: rgba(248, 250, 252, 0.94);
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
      }

      .live-pill::before {
        content: "";
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #ef4444;
        box-shadow: 0 0 12px rgba(239, 68, 68, 0.78);
      }

      .overlay[hidden] {
        display: none;
      }

      .overlay.is-playing {
        background: transparent;
      }

      .overlay.is-playing .center-play {
        opacity: 0;
      }

      .overlay.is-playing .brand-corner {
        opacity: 0.92;
      }

      .overlay.is-hovered .center-play,
      .overlay.is-paused .center-play {
        opacity: 1;
      }

      video[hidden] {
        display: none;
      }

      .center-play {
        transition: opacity 220ms ease, transform 220ms ease;
      }

      @keyframes button-bump {
        0% {
          transform: scale(1);
        }
        40% {
          transform: scale(0.92);
        }
        100% {
          transform: scale(1);
        }
      }

      @keyframes pulse-ring {
        0% {
          opacity: 0.5;
          transform: scale(0.88);
        }
        100% {
          opacity: 0;
          transform: scale(1.45);
        }
      }

      @keyframes spin {
        to {
          transform: rotate(360deg);
        }
      }

      @media (max-width: 640px) {
        body {
          padding: 0;
        }

        .play-button {
          width: 78px;
          height: 78px;
        }

        .pulse-ring {
          width: 78px;
          height: 78px;
        }

        .player-shell {
          width: 100%;
          max-height: 100vh;
          border-radius: 0;
        }

        .brand-corner {
          top: 10px;
          left: 10px;
          font-size: 10px;
          padding: 8px 11px;
        }

        .live-corner {
          top: 10px;
          right: 10px;
        }

        .controls-shell {
          padding: 28px 10px 10px;
        }

        .control-row {
          gap: 8px;
        }

        .control-btn {
          width: 36px;
          height: 36px;
        }

        .volume-wrap {
          width: 0;
        }

        .volume-wrap.open {
          width: 72px;
        }

        .time-label {
          font-size: 12px;
        }
      }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
    <script src="https://cdn.dashjs.org/latest/dash.all.min.js"></script>
  </head>
  <body>
    <main class="player-shell">
      <video
        id="player"
        playsinline
        ${autoplay ? "autoplay" : ""}
        ${muted ? "muted" : ""}
      ></video>
      <div id="overlay" class="overlay">
        <div class="brand-corner">BangBot Player</div>
        <div class="live-corner">
          <div id="livePill" class="live-pill" hidden>Live</div>
        </div>
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
          <div class="seek-wrap">
            <input id="seekbar" class="seekbar" type="range" min="0" max="1000" value="0" step="1" aria-label="Seek" />
          </div>
          <div class="control-row">
              <div class="control-group">
                <button id="controlPlay" class="control-btn" type="button" aria-label="Play">
                  <svg id="controlPlayIcon" viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M8 5.14v13.72c0 .77.83 1.25 1.5.86l10.5-6.86a1 1 0 0 0 0-1.72L9.5 4.28A1 1 0 0 0 8 5.14Z"></path>
                  </svg>
                </button>
                <div id="timeLabel" class="time-label">0:00 / 0:00</div>
              </div>
              <div class="control-group right">
                <button id="muteButton" class="control-btn" type="button" aria-label="Mute">
                  <svg id="muteIcon" viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M14.82 5.18a.75.75 0 0 1 1.06 0A8.94 8.94 0 0 1 18.5 12a8.94 8.94 0 0 1-2.62 6.82.75.75 0 0 1-1.06-1.06A7.44 7.44 0 0 0 17 12a7.44 7.44 0 0 0-2.18-5.76.75.75 0 0 1 0-1.06ZM4.5 9.5a1 1 0 0 1 1-1H8l4.1-3.28c.66-.53 1.65-.06 1.65.79v11.98c0 .85-.99 1.32-1.65.79L8 15.5H5.5a1 1 0 0 1-1-1v-5Z"></path>
                  </svg>
                </button>
                <div id="volumeWrap" class="volume-wrap">
                  <input id="volumeSlider" class="volume-slider" type="range" min="0" max="100" value="${muted ? 0 : 100}" step="1" aria-label="Volume" />
                </div>
                <button id="fullscreenButton" class="control-btn" type="button" aria-label="Fullscreen">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M7 3a1 1 0 0 1 0 2H5v2a1 1 0 1 1-2 0V4a1 1 0 0 1 1-1h3Zm14 0a1 1 0 0 1 1 1v3a1 1 0 1 1-2 0V5h-2a1 1 0 1 1 0-2h3ZM4 16a1 1 0 0 1 1 1v2h2a1 1 0 1 1 0 2H4a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1Zm17 0a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-3a1 1 0 1 1 0-2h2v-2a1 1 0 0 1 1-1Z"></path>
                  </svg>
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

      function syncFrameRatio() {
        if (!video.videoWidth || !video.videoHeight) {
          return;
        }

        playerShell.style.setProperty("--frame-ratio", video.videoWidth + " / " + video.videoHeight);
      }

      function formatTime(seconds) {
        if (!Number.isFinite(seconds) || seconds < 0) {
          return "0:00";
        }

        const whole = Math.floor(seconds);
        const hours = Math.floor(whole / 3600);
        const minutes = Math.floor((whole % 3600) / 60);
        const secs = whole % 60;

        if (hours > 0) {
          return hours + ":" + String(minutes).padStart(2, "0") + ":" + String(secs).padStart(2, "0");
        }

        return minutes + ":" + String(secs).padStart(2, "0");
      }

      function setRangeProgress(element, value, max) {
        const percent = max > 0 ? (value / max) * 100 : 0;
        element.style.setProperty("--value", percent + "%");
      }

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
        const progress = duration > 0 ? (current / duration) * 1000 : 0;
        if (!isSeeking) {
          seekbar.value = String(progress);
        }
        setRangeProgress(seekbar, Number(seekbar.value || 0), 1000);
      }

      function updateVolumeUi() {
        const volumeValue = video.muted ? 0 : Math.round(video.volume * 100);
        volumeSlider.value = String(volumeValue);
        setRangeProgress(volumeSlider, volumeValue, 100);
        muteButton.setAttribute("aria-label", video.muted || video.volume === 0 ? "Unmute" : "Mute");

        if (video.muted || video.volume === 0) {
          muteIcon.innerHTML = '<path d="M4.5 9.5a1 1 0 0 1 1-1H8l4.1-3.28c.66-.53 1.65-.06 1.65.79v11.98c0 .85-.99 1.32-1.65.79L8 15.5H5.5a1 1 0 0 1-1-1v-5Z"></path><path d="M17.28 7.78a.75.75 0 1 1 1.06-1.06L21.62 10a.75.75 0 0 1 0 1.06l-3.28 3.28a.75.75 0 1 1-1.06-1.06L19.5 11.06l-2.22-2.22Z"></path>';
        } else {
          muteIcon.innerHTML = '<path d="M14.82 5.18a.75.75 0 0 1 1.06 0A8.94 8.94 0 0 1 18.5 12a8.94 8.94 0 0 1-2.62 6.82.75.75 0 0 1-1.06-1.06A7.44 7.44 0 0 0 17 12a7.44 7.44 0 0 0-2.18-5.76.75.75 0 0 1 0-1.06ZM4.5 9.5a1 1 0 0 1 1-1H8l4.1-3.28c.66-.53 1.65-.06 1.65.79v11.98c0 .85-.99 1.32-1.65.79L8 15.5H5.5a1 1 0 0 1-1-1v-5Z"></path>';
        }
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
        if (!${safeControls}) {
          return;
        }

        controlsShell.classList.remove("hidden");
        clearTimeout(controlsHideTimer);

        if (!video.paused && !video.ended) {
          controlsHideTimer = setTimeout(() => {
            controlsShell.classList.add("hidden");
          }, 2200);
        }
      }

      function toggleVolumePanel(forceOpen) {
        const nextState = typeof forceOpen === "boolean"
          ? forceOpen
          : !volumeWrap.classList.contains("open");
        volumeWrap.classList.toggle("open", nextState);
      }

      function shouldIgnoreShellClick(event) {
        if (controlsShell.contains(event.target)) {
          return true;
        }

        if (event.target === playButton || playButton.contains(event.target)) {
          return true;
        }

        if (event.target.closest("button") || event.target.closest("input")) {
          return true;
        }

        if (${safeControls}) {
          showControls();
        }

        if (window.getSelection && String(window.getSelection())) {
          return true;
        }

        return false;
      }

      function togglePlayback(scope) {
        if (!sourcePrepared && streamType === "hls" && hlsInstance) {
          reportError(scope + "_before_hls_ready", { sourceUrl });
        }

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

        playPromise
          .then(() => {
            animateButton();
            syncPlayButton();
          })
          .catch((error) => {
            syncPlayButton();
            reportError(scope, {
              message: error && error.message ? error.message : String(error),
              name: error && error.name ? error.name : null,
            });
          });
      }

      function reportError(scope, details) {
        const payload = JSON.stringify({
          scope,
          details,
          sourceUrl,
          streamType,
          page: window.location.href,
          userAgent: navigator.userAgent,
          timestamp: new Date().toISOString(),
        });

        if (navigator.sendBeacon) {
          navigator.sendBeacon("/__client-error", payload);
          return;
        }

        fetch("/__client-error", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: payload,
          keepalive: true,
        }).catch(() => {});
      }

      function failSilently(scope, details) {
        video.hidden = true;
        overlay.hidden = true;
        reportError(scope, details);
      }

      function setBufferingState(isBuffering) {
        playButton.classList.toggle("is-buffering", isBuffering);
      }

      function loadHls() {
        if ((engine === "hlsjs" || engine === "auto") && window.Hls && window.Hls.isSupported()) {
          hlsInstance = new window.Hls({
            enableWorker: true,
            lowLatencyMode: true,
          });

          hlsInstance.loadSource(sourceUrl);
          hlsInstance.attachMedia(video);
          hlsInstance.on(window.Hls.Events.MANIFEST_PARSED, () => {
            sourcePrepared = true;
            updateTimeUi();
          });
          hlsInstance.on(window.Hls.Events.ERROR, (_, data) => {
            reportError("hlsjs_error", data);

            if (data?.fatal) {
              video.hidden = true;
              overlay.hidden = true;
            }
          });
          hlsInstance.on(window.Hls.Events.BUFFER_STALLED, () => {
            setBufferingState(true);
          });
          hlsInstance.on(window.Hls.Events.FRAG_BUFFERED, () => {
            setBufferingState(false);
          });
          video.addEventListener("error", () => {
            reportError("hlsjs_media_error", {
              code: video.error ? video.error.code : null,
            });
          });
          return;
        }

        if ((engine === "native" || engine === "auto") && video.canPlayType("application/vnd.apple.mpegurl")) {
          video.src = sourceUrl;
          video.addEventListener("loadedmetadata", () => {
            sourcePrepared = true;
          }, { once: true });
          video.addEventListener("error", () => {
            failSilently("hls_native_playback_error", {
              code: video.error ? video.error.code : null,
            });
          });
          return;
        }

        failSilently("hls_not_supported", {
          reason: "Browser ini tidak mendukung HLS lewat engine yang dipilih.",
          engine,
        });
      }

      function loadDash() {
        if (window.dashjs) {
          dashInstance = window.dashjs.MediaPlayer().create();
          dashInstance.initialize(video, sourceUrl, ${safeAutoplay});
          sourcePrepared = true;
          dashInstance.on("error", (event) => {
            failSilently("dash_error", event);
          });
          dashInstance.on("bufferStalled", () => {
            setBufferingState(true);
          });
          dashInstance.on("playbackPlaying", () => {
            setBufferingState(false);
          });
          return;
        }

        failSilently("dash_library_load_failed", { reason: "Library DASH tidak berhasil dimuat." });
      }

      if (streamType === "hls") {
        loadHls();
      } else if (streamType === "dash") {
        loadDash();
      } else {
        failSilently("unknown_stream_type", { reason: "Tipe stream tidak dikenali." });
      }

      playButton.addEventListener("click", () => {
        togglePlayback("manual_play");
      });

      controlPlay.addEventListener("click", () => {
        togglePlayback("control_play");
      });

      muteButton.addEventListener("click", () => {
        const panelOpen = volumeWrap.classList.contains("open");
        if (!panelOpen) {
          toggleVolumePanel(true);
          showControls();
          return;
        }

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

      seekbar.addEventListener("input", () => {
        isSeeking = true;
        updateTimeUi();
        showControls();
      });

      seekbar.addEventListener("change", () => {
        if (Number.isFinite(video.duration) && video.duration > 0) {
          video.currentTime = Number(seekbar.value) / 1000 * video.duration;
        }
        isSeeking = false;
        updateTimeUi();
      });

      fullscreenButton.addEventListener("click", async () => {
        try {
          if (document.fullscreenElement) {
            await document.exitFullscreen();
          } else {
            await playerShell.requestFullscreen();
          }
        } catch (error) {
          reportError("fullscreen_failed", {
            message: error && error.message ? error.message : String(error),
          });
        }
      });

      playerShell.addEventListener("click", (event) => {
        if (shouldIgnoreShellClick(event)) {
          return;
        }
        togglePlayback("shell_click");
      });

      video.addEventListener("click", (event) => {
        if (shouldIgnoreShellClick(event)) {
          return;
        }
        togglePlayback("video_click");
      });

      pulseRing.addEventListener("animationend", () => {
        pulseRing.classList.remove("active");
      });

      playerShell.addEventListener("pointermove", () => {
        overlay.classList.add("is-hovered");
        showControls();
      });

      playerShell.addEventListener("pointerleave", () => {
        overlay.classList.remove("is-hovered");
        toggleVolumePanel(false);
        if (!video.paused && !video.ended && ${safeControls}) {
          controlsShell.classList.add("hidden");
        }
      });

      video.addEventListener("play", syncPlayButton);
      video.addEventListener("pause", syncPlayButton);
      video.addEventListener("ended", syncPlayButton);
      video.addEventListener("timeupdate", updateTimeUi);
      video.addEventListener("loadedmetadata", syncFrameRatio);
      video.addEventListener("loadedmetadata", updateTimeUi);
      video.addEventListener("durationchange", updateTimeUi);
      video.addEventListener("volumechange", updateVolumeUi);
      video.addEventListener("waiting", () => setBufferingState(true));
      video.addEventListener("playing", () => {
        setBufferingState(false);
        showControls();
      });
      video.addEventListener("canplay", () => setBufferingState(false));
      video.addEventListener("seeking", () => setBufferingState(true));
      video.addEventListener("seeked", () => setBufferingState(false));

      document.addEventListener("fullscreenchange", () => {
        showControls();
      });

      syncPlayButton();
      updateVolumeUi();
      updateTimeUi();
      showControls();

      window.addEventListener("error", (event) => {
        failSilently("window_error", {
          message: event.message,
          filename: event.filename,
          lineno: event.lineno,
          colno: event.colno,
        });
      });

      window.addEventListener("unhandledrejection", (event) => {
        failSilently("unhandled_rejection", {
          reason: String(event.reason),
        });
      });
    </script>
  </body>
</html>`;
}

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  const publicOrigin = getPublicOrigin(request);

  try {
    if (requestUrl.pathname === "/__client-error" && request.method === "POST") {
      let rawBody = "";

      request.on("data", (chunk) => {
        rawBody += chunk;
      });

      request.on("end", () => {
        try {
          const parsedBody = rawBody ? JSON.parse(rawBody) : {};
          logError("client_error", parsedBody);
        } catch {
          logError("client_error_parse_failed", { rawBody });
        }

        sendEmpty(response, 204);
      });

      request.on("error", (error) => {
        logError("client_error_request_failed", error);
        sendEmpty(response, 204);
      });

      return;
    }

    if (request.method !== "GET") {
      logError("invalid_method", {
        method: request.method,
        path: requestUrl.pathname,
      });
      sendEmpty(response, 405);
      return;
    }

    if (requestUrl.pathname === "/") {
      sendJson(response, 200, buildLandingPage(requestUrl));
      return;
    }

    if (requestUrl.pathname === "/favicon.ico") {
      sendEmpty(response, 204);
      return;
    }

    if (requestUrl.pathname === "/health") {
      sendJson(response, 200, {
        status: "ok",
        uptimeSeconds: Math.round(process.uptime()),
        timestamp: new Date().toISOString(),
      });
      return;
    }

    if (requestUrl.pathname === "/proxy") {
      const token = requestUrl.searchParams.get("token");
      const payload = decodeEmbedToken(token);

      if (!payload || typeof payload.proxyUrl !== "string") {
        logError("proxy_invalid_token", {
          path: requestUrl.pathname,
          query: requestUrl.search,
        });
        sendEmpty(response, 400);
        return;
      }

      const validation = validateSource(payload.proxyUrl);
      if (validation.error) {
        logError("proxy_validation_failed", {
          error: validation.error,
          proxyUrl: payload.proxyUrl,
        });
        sendEmpty(response, 400);
        return;
      }

      const upstreamHeaders = {
        "user-agent": request.headers["user-agent"] || "embedstreaming-proxy/1.0",
      };

      if (request.headers.range) {
        upstreamHeaders.range = request.headers.range;
      }

      const upstreamResponse = await fetch(validation.sourceUrl, {
        method: "GET",
        headers: upstreamHeaders,
        redirect: "follow",
      });

      const contentType = upstreamResponse.headers.get("content-type") || "application/octet-stream";
      const responseHeaders = {
        "Cache-Control": "no-store",
        "Content-Type": contentType,
        "Accept-Ranges": upstreamResponse.headers.get("accept-ranges") || "bytes",
      };

      const contentLength = upstreamResponse.headers.get("content-length");
      const contentRange = upstreamResponse.headers.get("content-range");
      if (contentLength) {
        responseHeaders["Content-Length"] = contentLength;
      }
      if (contentRange) {
        responseHeaders["Content-Range"] = contentRange;
      }

      const origin = publicOrigin;
      const bodyBuffer = await readResponseBody(upstreamResponse);

      if (contentType.includes("application/vnd.apple.mpegurl") || contentType.includes("audio/mpegurl") || validation.sourceUrl.toLowerCase().endsWith(".m3u8")) {
        const rewritten = rewriteHlsManifest(bodyBuffer.toString("utf8"), upstreamResponse.url, origin);
        responseHeaders["Content-Length"] = String(Buffer.byteLength(rewritten));
        response.writeHead(upstreamResponse.status, responseHeaders);
        response.end(rewritten);
        return;
      }

      if (contentType.includes("application/dash+xml") || validation.sourceUrl.toLowerCase().endsWith(".mpd")) {
        const rewritten = rewriteDashManifest(bodyBuffer.toString("utf8"), upstreamResponse.url, origin);
        responseHeaders["Content-Length"] = String(Buffer.byteLength(rewritten));
        response.writeHead(upstreamResponse.status, responseHeaders);
        response.end(rewritten);
        return;
      }

      response.writeHead(upstreamResponse.status, responseHeaders);
      response.end(bodyBuffer);
      return;
    }

    if (requestUrl.pathname === "/sign") {
      const resolved = resolveEmbedParams(requestUrl);
      if (resolved.error) {
        logError("sign_token_invalid", {
          error: resolved.error,
          query: requestUrl.search,
        });
        sendEmpty(response, 400);
        return;
      }

      const validation = validateSource(resolved.sourceUrl);
      if (validation.error) {
        logError("sign_validation_failed", {
          error: validation.error,
          path: requestUrl.pathname,
          query: requestUrl.search,
        });
        sendEmpty(response, 400);
        return;
      }

      const requestedType = (resolved.requestedType || "auto").toLowerCase();
      const inferredType = guessStreamType(validation.sourceUrl);
      const streamType = requestedType === "auto" ? inferredType : requestedType;

      if (!["hls", "dash"].includes(streamType)) {
        logError("sign_invalid_stream_type", {
          requestedType,
          inferredType,
          sourceUrl: validation.sourceUrl,
        });
        sendEmpty(response, 400);
        return;
      }

      const engine = (resolved.engine || "auto").toLowerCase();
      if (!["auto", "native", "hlsjs"].includes(engine)) {
        logError("sign_invalid_engine", {
          engine,
          sourceUrl: validation.sourceUrl,
        });
        sendEmpty(response, 400);
        return;
      }

      const token = createEmbedToken(buildEmbedTokenPayload({
        sourceUrl: validation.sourceUrl,
        streamType,
        autoplay: parseBoolean(resolved.autoplay),
        muted: parseBoolean(resolved.muted),
        controls: parseBoolean(resolved.controls, true),
        title: resolved.title,
        engine,
      }));

      sendJson(response, 200, {
        token,
        embedUrl: `${publicOrigin}/embed?token=${token}`,
      });
      return;
    }

    if (requestUrl.pathname === "/embed") {
      const resolved = resolveEmbedParams(requestUrl);
      if (resolved.error) {
        logError("embed_token_invalid", {
          error: resolved.error,
          path: requestUrl.pathname,
          query: requestUrl.search,
        });
        sendEmpty(response, 400);
        return;
      }

      const validation = validateSource(resolved.sourceUrl);
      if (validation.error) {
        logError("embed_validation_failed", {
          error: validation.error,
          path: requestUrl.pathname,
          query: requestUrl.search,
        });
        sendEmpty(response, 400);
        return;
      }

      const requestedType = (resolved.requestedType || "auto").toLowerCase();
      const inferredType = guessStreamType(validation.sourceUrl);
      const streamType = requestedType === "auto" ? inferredType : requestedType;

      if (!["hls", "dash"].includes(streamType)) {
        logError("embed_invalid_stream_type", {
          requestedType,
          inferredType,
          sourceUrl: validation.sourceUrl,
        });
        sendEmpty(response, 400);
        return;
      }

      const engine = (resolved.engine || "auto").toLowerCase();

      if (!["auto", "native", "hlsjs"].includes(engine)) {
        logError("embed_invalid_engine", {
          engine,
          sourceUrl: validation.sourceUrl,
        });
        sendEmpty(response, 400);
        return;
      }

      const html = buildEmbedHtml({
        sourceUrl: validation.sourceUrl,
        playbackUrl: getProxyUrl(publicOrigin, validation.sourceUrl),
        streamType,
        autoplay: parseBoolean(resolved.autoplay),
        muted: parseBoolean(resolved.muted),
        controls: parseBoolean(resolved.controls, true),
        title: resolved.title,
        engine,
      });

      void runStreamProbe(validation.sourceUrl, streamType);
      sendHtml(response, 200, html);
      return;
    }

    logError("route_not_found", {
      method: request.method,
      path: requestUrl.pathname,
    });
    sendEmpty(response, 404);
  } catch (error) {
    logError("request_handler_failed", {
      method: request.method,
      path: requestUrl.pathname,
      error: error && error.stack ? error.stack : String(error),
    });
    sendEmpty(response, 500);
  }
});

server.on("error", (error) => {
  if (error && error.code === "EADDRINUSE") {
    logError("server_port_in_use", `Port ${PORT} sedang dipakai proses lain. Ubah PORT atau matikan proses yang bentrok.`);
    process.exit(1);
  }

  logError("server_start_failed", error);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`embedstreaming listening on http://${HOST}:${PORT}`);
});
