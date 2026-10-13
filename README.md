# Order Documentation Tracker

Standalone web app for a valve manufacturer to track customer-document submission per order
(PO receipt to week 12 or any week, with custom weekly milestones). Works on PC, tablet and mobile.

* No build step. Node 22, Postgres (`pg`) and Vercel Blob.
* Roles: **viewer** (read-only), **editor** (create/update orders, pass milestones, attach files), **admin** (+ settings, users, delete orders).
* Open dashboard for everyone (switchable to login-required in Settings).

## Behaviour notes
* **Dashboard years:** the calendar year runs **September to August** (PO date 1 Sep 2025 to 31 Aug 2026 = "2025-26"). Pick a From / To year range; the status cards, milestone chart and order list follow it. All years are always loaded from the server, the year-by-year bars always show every year, and the search box looks through all years whatever range is selected.
* **Reminder days:** every milestone has its own "Remind N days before due" value (default 7), in Settings (default milestones) and in the order form. It drives the "Reminder window (due soon)" card and filter.
* **Order fields:** in the order form every field name can be renamed (tap the name) and the optional ones (email, est. delivery, mfr ref, doc weeks, plus any extra fields) can be removed with the cross and restored from "Removed fields". PO date, order no and customer can be renamed but not removed. Changes apply to that order only.
* **Customer email:** accepts several addresses (comma, semicolon, space or Enter between them, max 20). The reminder button addresses all of them.

## Deploy on Vercel

The app runs as one serverless function (`api/index.js` -> `lib/app.js`) with static files from `public/`.
Because Vercel has no persistent disk, data lives in **Postgres** and attachments in **Vercel Blob (private)**.

1. Push this folder to a GitHub/GitLab repo, then Vercel > Add New > Project > import it (Framework: Other; no build command).
2. Project > **Storage**: add a **Postgres** database (Neon, from the Marketplace) and connect it to the project. This sets `DATABASE_URL`.
3. Project > Storage: create a **Blob** store with **Private** access and connect it. This sets `BLOB_READ_WRITE_TOKEN`.
4. Project > Settings > Environment Variables, add: `ADMIN_PASSWORD` (first start only), `SECRET` (any long random string, e.g. `openssl rand -hex 32`).
   Optional: `ADMIN_USER` (default `admin`), `MAX_UPLOAD_MB` (default 100), `SESSION_DAYS` (default 7).
5. Deploy. Tables are created automatically on the first request and the admin account is created from `ADMIN_USER` / `ADMIN_PASSWORD`.
   HTTPS and custom domains are handled by Vercel.

Lost password: `vercel env pull .env.local` then `node --env-file=.env.local reset-admin.js admin NewPassword123`.

**Local development:** `npm install`, put `DATABASE_URL` and `BLOB_READ_WRITE_TOKEN` in `.env.local`, then `node --env-file=.env.local server.js`.

**Backup:** use your Postgres provider's backups (Neon point-in-time restore) and export the Blob store if needed.

## Offline / intranet use
The page loads React and Babel from cdnjs. For a server with no internet access, download these into `public/vendor/`
and change the three `<script src>` lines in `public/index.html` to `/vendor/...`:

    https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js
    https://cdnjs.cloudflare.com/ajax/libs/react-dom/18.2.0/umd/react-dom.production.min.js
    https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/7.23.5/babel.min.js

## Security notes
* Passwords: scrypt-hashed. Sessions: signed HttpOnly cookie; reset/deactivate logs the user out. Login attempts are rate-limited.
* Writes need a custom header (CSRF protection). Uploads go directly from the browser to a private Blob store and are served through the app (login rules apply). They are served as downloads (only PDF/PNG/JPG/GIF/WebP display inline).
* Order changes use revision checks, so two editors cannot silently overwrite each other. Every pass, remark, edit and file change is logged with user and time.
* Attachments are visible to anyone who can view the dashboard. Turn the open dashboard off if documents are confidential.
* Not included: automatic email sending (the reminder button opens your mail app), password-reset by email, SSO.

## Files
`lib/app.js` API + auth + Postgres + Blob uploads · `api/index.js` Vercel entry · `server.js` local dev only · `public/index.html` the whole UI · `vercel.json` routing.
