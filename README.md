# AgriMill ERP

## Deploy to Render

1. Push this repository to GitHub.
2. In Render, choose **New → Blueprint**, connect the repository, and deploy the `render.yaml` Blueprint.
3. Wait for the deploy and open the service URL. Render checks `/api/health` to verify the server is ready.

The Blueprint provisions a persistent disk at `/var/data` for SQLite. The database survives deploys and restarts, but the disk is attached to one service instance; do not scale this SQLite-backed service to multiple instances. The disk is a paid Render resource.

## Gmail OTP and accounts

Before deploying, create a Google App Password for `sachinn.agarrwal@gmail.com` (Google requires 2-Step Verification). Set it as the `GMAIL_APP_PASSWORD` secret in Render; `GMAIL_USER` is configured by the Blueprint. Never commit or share the App Password.

On the first visit, choose **Set up administrator**. A verification code is emailed to the master Gmail account; use it to create the permanent administrator password. Sign in with `sachinn.agarrwal@gmail.com` as the master user ID.

The administrator can invite staff from **User management** by assigning a unique user ID, name, email, and department. Each invitee verifies the emailed OTP and creates their own permanent password. The administrator can resend invitations, send password-reset codes, deactivate/reactivate accounts, and delete accounts. Department data APIs require a valid session and enforce department access.

Passwords are stored as salted scrypt hashes. OTP codes expire after 10 minutes and are limited to five verification attempts. Sessions use secure, HTTP-only cookies and expire after 12 hours. A persistent disk is required for SQLite account, session, and application data.

For local development, run `npm install` and then `npm start`, then open `http://localhost:3000`. Do not open `index.html` directly: sign-in and data storage require the server. The SQLite database defaults to `data.sqlite` in the project directory; set `DATABASE_PATH` to use another location.
