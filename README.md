# AgriMill ERP

## Deploy to Render

1. Push this repository to GitHub.
2. In Render, choose **New → Blueprint**, connect the repository, and deploy the `render.yaml` Blueprint.
3. Before deploying, set the Render secret `ADMIN_INITIAL_PASSWORD` to the initial administrator password (`Admin@1212` if using the requested default).
4. Wait for the deploy and open the service URL. Render checks `/api/health` to verify the server is ready.

The Blueprint provisions a persistent disk at `/var/data` for SQLite. The database survives deploys and restarts, but the disk is attached to one service instance; do not scale this SQLite-backed service to multiple instances. The disk is a paid Render resource.

## Administrator and department accounts

On the first visit, choose **Set up administrator**. Use `sachinn.agarrwal@gmail.com` as the master login ID and the password configured as `ADMIN_INITIAL_PASSWORD`. The ID is only a username; this application does not send email or connect to Gmail. The first sign-in requires changing the initial password in the **Profile** section before accessing the dashboard. Password changes remain available from the profile.

When upgrading a database created by the former email/OTP login, the first startup resets the master password to `ADMIN_INITIAL_PASSWORD`, invalidates existing sessions, and removes the OTP table. Set the secret before deploying this update.

The administrator can create accounts from **User management** by assigning a unique user ID, name, department, and temporary password. Give that temporary password directly to the intended user through a secure channel. Users must change it after signing in. The administrator can reset temporary passwords, deactivate/reactivate accounts, and delete accounts. Resets revoke the user's existing sessions and require another password change at next sign-in. Department data APIs require a valid session and enforce department access.

Passwords are stored as salted scrypt hashes. Sessions use secure, HTTP-only cookies and expire after 12 hours. A persistent disk is required for SQLite account, session, and application data. Existing account contact addresses are migrated to internal placeholders; no mail service is configured.

For local development, run `npm install` and then `npm start`, then open `http://localhost:3000`. Do not open `index.html` directly: sign-in and data storage require the server. The SQLite database defaults to `data.sqlite` in the project directory; set `DATABASE_PATH` to use another location.
