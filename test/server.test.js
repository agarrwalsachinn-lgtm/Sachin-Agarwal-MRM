const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const test = require("node:test");
const sqlite3 = require("sqlite3").verbose();

const repoRoot = path.resolve(__dirname, "..");
const passwordSalt = "00112233445566778899aabbccddeeff";
let testDirectory;
let baseUrl;
let server;

function run(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, error => error ? reject(error) : resolve());
  });
}

function close(db) {
  return new Promise((resolve, reject) => {
    db.close(error => error ? reject(error) : resolve());
  });
}

async function unusedPort() {
  const listener = net.createServer();
  await new Promise((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", resolve);
  });
  const { port } = listener.address();
  await new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
  return port;
}

async function seedDatabase(databasePath) {
  const db = new sqlite3.Database(databasePath);
  const users = [
    ["sachinn.agarrwal@gmail.com", "sachinn.agarrwal@gmail.com", "Sachin Agarwal", "admin", "master-password-123", 1, 1, 1],
    ["inv-001", "inv@example.com", "Inventory Staff", "inventory", "staff-password-123", 1, 1, 0],
    ["sto-001", "stores@example.com", "Stores Staff", "stores", "stores-password-123", 1, 1, 0],
    ["prd-001", "production@example.com", "Production Staff", "production", "production-password-123", 1, 1, 0]
  ];
  await run(db, `CREATE TABLE auth_users (
    user_id TEXT PRIMARY KEY COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    department_id TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 0,
    is_master INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`);
  for (const [userId, email, name, departmentId, password, emailVerified, active, master] of users) {
    const hash = crypto.scryptSync(password, passwordSalt, 64).toString("hex");
    await run(db,
      `INSERT INTO auth_users
        (user_id, email, name, department_id, password_salt, password_hash, email_verified, is_active, is_master, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [userId, email, name, departmentId, passwordSalt, hash, emailVerified, active, master, Date.now()]
    );
  }
  await run(db, "CREATE TABLE storage (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
  const inventoryItems = [
    { sku: "INV-001", name: "Rice", category: "Raw material", balances: { "Main warehouse": 50 } },
    { sku: "STO-001", name: "HDPE Bags", category: "Packaging", balances: { "Packaging store": 100 } }
  ];
  await run(db, "INSERT INTO storage VALUES (?, ?)", ["agrimill-inventory-items", JSON.stringify(inventoryItems)]);
  await run(db, "INSERT INTO storage VALUES (?, ?)", ["agrimill-stockMovement", JSON.stringify([
    ["MOV-001", "2026-01-01", "09:00", "INV-001", "Rice", "Receipt"],
    ["MOV-002", "2026-01-01", "10:00", "STO-001", "HDPE Bags", "Receipt"]
  ])]);
  await run(db, "INSERT INTO storage VALUES (?, ?)", ["agrimill-inventory-purchases", JSON.stringify([
    ["PUR-001", "2026-01-01", "09:00", "INV-001", "Rice", "Raw material"],
    ["PUR-002", "2026-01-01", "10:00", "STO-001", "HDPE Bags", "Packaging"]
  ])]);
  await run(db, "INSERT INTO storage VALUES (?, ?)", ["agrimill-stores", "legacy stores data"]);
  await run(db, "INSERT INTO storage VALUES (?, ?)", ["agrimill-purchases", JSON.stringify([
    ["PUR-000", "Private Supplier", "2026-01-01", "5000", "2026-01-05", "Raw material", "10", "500", "50", "RST-001", "Main warehouse", "Paid"]
  ])]);
  await close(db);
}

async function signIn(userId, password) {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId, password })
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  return { cookie: response.headers.get("set-cookie").split(";")[0], payload };
}

async function api(url, cookie, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (cookie) headers.Cookie = cookie;
  return fetch(`${baseUrl}${url}`, { ...options, headers });
}

test.before(async () => {
  testDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "agrimill-auth-test-"));
  const databasePath = path.join(testDirectory, "test.sqlite");
  await seedDatabase(databasePath);
  const port = await unusedPort();
  baseUrl = `http://127.0.0.1:${port}`;
  server = spawn(process.execPath, ["server.js"], {
    cwd: repoRoot,
    env: { ...process.env, DATABASE_PATH: databasePath, PORT: String(port), NODE_ENV: "test" },
    stdio: "ignore"
  });

  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`Test server exited with code ${server.exitCode}.`);
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error("Test server did not become ready.");
});

test.after(async () => {
  if (server && server.exitCode === null) {
    server.kill();
    await Promise.race([
      once(server, "exit"),
      new Promise(resolve => setTimeout(resolve, 3000))
    ]);
  }
  if (testDirectory) fs.rmSync(testDirectory, { recursive: true, force: true });
});

test("requires a session before exposing stored data", async () => {
  const response = await api("/api/storage");
  assert.equal(response.status, 401);
});

test("limits staff storage access to their department", async () => {
  const { cookie, payload } = await signIn("inv-001", "staff-password-123");
  assert.equal(payload.user.departmentId, "inventory");

  const response = await api("/api/storage", cookie);
  const data = await response.json();
  assert.deepEqual(JSON.parse(data["agrimill-inventory-items"]).map(item => item.sku), ["INV-001"]);
  assert.equal(JSON.parse(data["agrimill-stockMovement"]).length, 1);
  assert.equal(JSON.parse(data["agrimill-inventory-purchases"]).length, 1);
  assert.equal(data["agrimill-stores"], undefined);
  assert.equal(data["agrimill-purchases"], undefined);

  const deniedRead = await api("/api/storage?key=agrimill-stores", cookie);
  assert.equal(deniedRead.status, 403);
  const deniedWrite = await api("/api/storage", cookie, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: "agrimill-purchases", value: "unauthorized" })
  });
  assert.equal(deniedWrite.status, 403);

  const update = await api("/api/storage", cookie, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      key: "agrimill-inventory-items",
      value: JSON.stringify([{ ...JSON.parse(data["agrimill-inventory-items"])[0], balances: { "Main warehouse": 42 } }])
    })
  });
  assert.equal(update.status, 200);

  const stores = await signIn("sto-001", "stores-password-123");
  const storesData = await api("/api/storage", stores.cookie);
  const storesPayload = await storesData.json();
  assert.deepEqual(JSON.parse(storesPayload["agrimill-inventory-items"]).map(item => item.sku), ["STO-001"]);

  const admin = await signIn("sachinn.agarrwal@gmail.com", "master-password-123");
  const allData = await api("/api/storage", admin.cookie);
  const adminItems = JSON.parse((await allData.json())["agrimill-inventory-items"]);
  assert.equal(adminItems.find(item => item.sku === "STO-001").balances["Packaging store"], 100);
  assert.equal(adminItems.find(item => item.sku === "INV-001").balances["Main warehouse"], 42);

  const production = await signIn("prd-001", "production-password-123");
  const purchases = await api("/api/storage?key=agrimill-purchases", production.cookie);
  const paddyRecords = JSON.parse((await purchases.json()).value);
  assert.equal(paddyRecords[0][1], "—");
  assert.equal(paddyRecords[0][3], "—");
  const purchaseWrite = await api("/api/storage", production.cookie, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: "agrimill-purchases", value: "[]" })
  });
  assert.equal(purchaseWrite.status, 403);
});

test("only the master administrator can manage department accounts", async () => {
  const staff = await signIn("inv-001", "staff-password-123");
  const denied = await api("/api/admin/users", staff.cookie);
  assert.equal(denied.status, 403);

  const admin = await signIn("sachinn.agarrwal@gmail.com", "master-password-123");
  const response = await api("/api/admin/users", admin.cookie);
  assert.equal(response.status, 200);
  const { users } = await response.json();
  assert.equal(users.length, 3);
  assert.ok(users.some(user => user.userId === "inv-001"));

  const deactivate = await api("/api/admin/users/inv-001/status", admin.cookie, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ active: false })
  });
  assert.equal(deactivate.status, 200);
  const revokedSession = await api("/api/storage", staff.cookie);
  assert.equal(revokedSession.status, 401);

  const reactivate = await api("/api/admin/users/inv-001/status", admin.cookie, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ active: true })
  });
  assert.equal(reactivate.status, 200);
  await signIn("inv-001", "staff-password-123");

  const logout = await api("/api/auth/logout", staff.cookie, { method: "POST" });
  assert.equal(logout.status, 200);
  const expiredSession = await api("/api/storage", staff.cookie);
  assert.equal(expiredSession.status, 401);
});

test("serves no demo credentials in the sign-in page", async () => {
  const response = await api("/");
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.doesNotMatch(html, /demo logins/i);
});
