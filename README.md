# embedstreaming

Backend minimal untuk halaman embed player HLS dan DASH.

## Menjalankan

```bash
npm start
```

Server default berjalan di `http://localhost:3000`.

## Endpoint

- `GET /`
  Mengembalikan info service dan contoh URL.

- `GET /health`
  Healthcheck sederhana.

- `GET /embed?src=<stream-url>&type=<auto|hls|dash>`
  Mengembalikan halaman HTML player yang siap dipakai di `iframe`.

## Query parameter `/embed`

- `src`
  URL stream HLS (`.m3u8`) atau DASH (`.mpd`).

- `type`
  Opsional. `auto` (default), `hls`, atau `dash`.

- `autoplay`
  Opsional. Default `false`. Isi `1`/`true` untuk mencoba autoplay.

- `muted`
  Opsional. Default `false`.

- `controls`
  Opsional. Default `true`.

- `title`
  Opsional. Judul halaman embed.

- `engine`
  Opsional. `auto` (default), `hlsjs`, atau `native`. Untuk HLS di Chrome/Edge biasanya lebih aman pakai `hlsjs`.

## Contoh

HLS:

```text
http://localhost:3000/embed?src=https%3A%2F%2Ftest-streams.mux.dev%2Fx36xhzz%2Fx36xhzz.m3u8
```

DASH:

```text
http://localhost:3000/embed?src=https%3A%2F%2Fdash.akamaized.net%2Fenvivio%2FEnvivioDash3%2Fmanifest.mpd
```

## Catatan

Player dijalankan di browser user, jadi origin stream tetap harus mengizinkan request media lewat CORS bila dibutuhkan player/library.

Response error untuk endpoint publik sengaja dibuat tanpa body. Detail error backend dan error playback dari browser dicatat ke terminal server.

Untuk source tertentu seperti Dens TV, server akan otomatis memakai preset header proxy yang lebih cocok tanpa perlu query tambahan manual.
