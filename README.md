# Order Documentation Tracker

Standalone web app for a valve manufacturer to track customer-document submission per order
(PO receipt to week 12 or any week, with custom weekly milestones). Works on PC, tablet and mobile.

* **No npm install, no build.** Server = Node.js 22.13+ only (built-in SQLite). One data folder.
* Roles: **viewer** (read-only), **editor** (create/update orders, pass milestones, attach files), **admin** (+ settings, users, delete orders).
* Open dashboard for everyone (switchable to login-required in Settings).

## Behaviour notes
* **Dashboard years:** the calendar year runs **September to August** (PO date 1 Sep 2025 to 31 Aug 2026 = "2025-26"). Pick a From / To year range; the status cards, milestone chart and order list follow it. All years are always loaded from the server, the year-by-year bars always show every year, and the search box looks through all years whatever range is selected.
* **Reminder days:** every milestone has its own "Remind N days before due" value (default 7), in Settings (default milestones) and in the order form. It drives the "Reminder window (due soon)" card and filter.
* **Order fields:** in the order form every field name can be renamed (tap the name) and the optional ones (email, est. delivery, mfr ref, doc weeks, plus any extra fields) can be removed with the cross and restored from "Removed fields". PO date, order no and customer can be renamed but not removed. Changes apply to that order only.
* **Customer email:** accepts several addresses (comma, semicolon, space or Enter between them, max 20). The reminder button addresses all of them.

## Run

    node server.js            # http://localhost:3000

First start prints the admin username/password in the console (or set `ADMIN_USER` / `ADMIN_PASSWORD`).
Log in, open **Settings**, set app and manufacturer name, default milestones, then create users.

## Deploy

**Docker:** `docker compose up -d --build` (data kept in `./data`).

**Linux server (systemd):** copy the folder to `/opt/tracker`, then `/etc/systemd/system/tracker.service`:

    [Service]
    WorkingDirectory=/opt/tracker
    Environment=PORT=3000 TRUST_PROXY=1 NODE_NO_WARNINGS=1
    ExecStart=/usr/bin/node server.js
    Restart=always
    User=www-data
    [Install]
    WantedBy=multi-user.target

then `systemctl enable --now tracker`.

**HTTPS (required for use over the internet):** put it behind a reverse proxy, e.g. Caddy:

    tracker.yourcompany.com {
        reverse_proxy localhost:3000
    }

(nginx: `proxy_pass http://127.0.0.1:3000;` with `proxy_set_header X-Forwarded-Proto $scheme;`,
`X-Forwarded-For`, and `client_max_body_size 30m;`.) Also works on Windows, or cloud hosts that run Node 22 or Docker.

**Backup:** copy the `data/` folder (database `tracker.db` plus `uploads/`). Stop the app or use SQLite's backup for a perfectly consistent copy.

## Offline / intranet use
The page loads React and Babel from cdnjs. For a server with no internet access, download these into `public/vendor/`
and change the three `<script src>` lines in `public/index.html` to `/vendor/...`:

    https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js
    https://cdnjs.cloudflare.com/ajax/libs/react-dom/18.2.0/umd/react-dom.production.min.js
    https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/7.23.5/babel.min.js

## Security notes
* Passwords: scrypt-hashed. Sessions: signed HttpOnly cookie; reset/deactivate logs the user out. Login attempts are rate-limited.
* Writes need a custom header (CSRF protection). Uploaded files are served as downloads (only PDF/PNG/JPG/GIF/WebP display inline).
* Order changes use revision checks, so two editors cannot silently overwrite each other. Every pass, remark, edit and file change is logged with user and time.
* Attachments are visible to anyone who can view the dashboard. Turn the open dashboard off if documents are confidential.
* Not included: automatic email sending (the reminder button opens your mail app), password-reset by email, SSO.

## Files
`server.js` API + auth + SQLite + uploads · `public/index.html` the whole UI · `data/` created at runtime.

## Deploy on Render
1. Push this folder to a GitHub/GitLab repo (`data/` and `.env` are git-ignored).
2. Render dashboard > New > Blueprint > select the repo (reads `render.yaml`). Enter an `ADMIN_PASSWORD` when asked.
   Manual alternative: New > Web Service, runtime Node, build `echo ok`, start `node server.js`, instance type **Starter or higher**,
   add a Disk mounted at `/var/data` (1 GB), env vars `NODE_VERSION=22`, `DATA_DIR=/var/data`, `TRUST_PROXY=1`, `ADMIN_PASSWORD=...`.
3. Open the `https://<name>.onrender.com` URL and log in as `admin`. HTTPS is automatic; add your own domain under Settings > Custom Domains.
Free instances have no persistent disk, so orders and uploads would be lost on every restart. Do not use them for real data.
Lost password: Render service > Shell > `node reset-admin.js admin NewPassword123`.
