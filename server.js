const crypto = require("crypto");
const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const port = process.env.PORT || 3000;
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, "data.sqlite");
const masterUserId = "sachinn.agarrwal@gmail.com";
const sessionCookie = "agrimill_session";
const sessionLifetimeMs = 12 * 60 * 60 * 1000;
const departmentModules = {
  admin: ["dashboard", "dailyReview", "editLog", "production", "inventory", "inventoryMovement", "inventoryPurchases", "stores", "storesPurchases", "stockMovement", "purchases", "purchaseOrders", "sales", "salesOrders", "brokerage", "accounting", "employees", "userManagement"],
  production: ["dashboard", "production", "inventory", "inventoryMovement"],
  inventory: ["dashboard", "inventory", "inventoryPurchases", "inventoryMovement"],
  stores: ["dashboard", "stores", "storesPurchases", "stockMovement"],
  purchase: ["dashboard", "purchases", "purchaseOrders"],
  sales: ["dashboard", "sales", "salesOrders", "brokerage", "inventory"],
  accounts: ["dashboard", "accounting", "purchases", "sales", "brokerage"],
  hr: ["dashboard", "employees"]
};
const departmentLabels = {
  admin: "Administrator",
  production: "Production",
  inventory: "Inventory",
  stores: "Stores",
  purchase: "Purchase",
  sales: "Sales",
  accounts: "Accounts",
  hr: "Human Resources"
};
const sharedStorageModules = {
  "inventory-items": ["inventory", "stores", "sales"],
  "stockMovement": ["stockMovement", "inventoryMovement", "sales"],
  "inventory-purchases": ["inventoryPurchases", "storesPurchases"],
  "paddy-purchase-migrations": ["purchases", "inventoryPurchases"]
};
const readOnlyStorageModules = {
  purchases: ["production"]
};
const requestLimits = new Map();
const db = new sqlite3.Database(dbPath);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) reject(error);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => error ? reject(error) : resolve(row));
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows));
  });
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function checkRateLimit(key, limit, windowMs) {
  const now = Date.now();
  const current = requestLimits.get(key);
  if (!current || now - current.startedAt >= windowMs) {
    requestLimits.set(key, { startedAt: now, count: 1 });
    return true;
  }
  if (current.count >= limit) return false;
  current.count += 1;
  return true;
}

function requireRateLimit(key, limit, windowMs) {
  if (!checkRateLimit(key, limit, windowMs)) {
    throw new HttpError(429, "Too many attempts. Please wait before trying again.");
  }
}

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) reject(error);
      else resolve({ salt, hash: derivedKey.toString("hex") });
    });
  });
}

function verifyPassword(password, salt, hash) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) reject(error);
      else {
        const expected = Buffer.from(hash, "hex");
        resolve(expected.length === derivedKey.length && crypto.timingSafeEqual(expected, derivedKey));
      }
    });
  });
}

function validatePassword(password) {
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    throw new HttpError(400, "Choose a password between 12 and 128 characters.");
  }
}

function getInitialAdminPassword() {
  const password = process.env.ADMIN_INITIAL_PASSWORD;
  if (typeof password !== "string" || password.length < 8 || password.length > 128) {
    throw new HttpError(503, "Set ADMIN_INITIAL_PASSWORD in Render before creating the administrator account.");
  }
  return password;
}

function publicUser(user) {
  return {
    accountId: user.user_id,
    name: user.name,
    departmentId: user.department_id,
    role: departmentLabels[user.department_id],
    isMaster: Boolean(user.is_master),
    mustChangePassword: Boolean(user.must_change_password)
  };
}

function cookieValue(req, name) {
  const cookie = (req.headers.cookie || "").split(";").map(part => part.trim())
    .find(part => part.startsWith(`${name}=`));
  return cookie ? decodeURIComponent(cookie.slice(name.length + 1)) : "";
}

function writeSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${sessionCookie}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${sessionLifetimeMs / 1000}${secure}`);
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${sessionCookie}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}

async function createSession(res, user) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + sessionLifetimeMs;
  await run("DELETE FROM auth_sessions WHERE expires_at <= ?", [Date.now()]);
  await run("INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)", [
    crypto.createHash("sha256").update(token).digest("hex"),
    user.user_id,
    expiresAt
  ]);
  writeSessionCookie(res, token);
  return publicUser(user);
}

const requireUser = asyncRoute(async (req, res, next) => {
  const token = cookieValue(req, sessionCookie);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    throw new HttpError(401, "Please sign in to continue.");
  }

  const user = await get(
    `SELECT u.user_id, u.name, u.department_id, u.is_master, u.must_change_password
     FROM auth_sessions s JOIN auth_users u ON u.user_id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_active = 1`,
    [crypto.createHash("sha256").update(token).digest("hex"), Date.now()]
  );
  if (!user) {
    clearSessionCookie(res);
    throw new HttpError(401, "Your session has expired. Please sign in again.");
  }

  req.user = user;
  if (user.must_change_password && !["/api/auth/password/change", "/api/auth/logout"].includes(req.path)) {
    throw new HttpError(403, "Change your temporary password from your profile before continuing.");
  }
  next();
});

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.is_master) {
    res.status(403).json({ error: "Administrator access is required." });
    return;
  }
  next();
}

function storageModules(key) {
  if (!key.startsWith("agrimill-") || key === "agrimill-user") return [];
  const moduleId = key.slice("agrimill-".length);
  if (sharedStorageModules[moduleId]) return sharedStorageModules[moduleId];
  if (readOnlyStorageModules[moduleId]) return [moduleId, ...readOnlyStorageModules[moduleId]];
  if (moduleId === "dryerBatches" || moduleId === "millingRuns") return ["production"];
  return [moduleId];
}

function canReadStorageKey(user, key) {
  return Boolean(user.is_master)
    || storageModules(key).some(moduleId => departmentModules[user.department_id]?.includes(moduleId));
}

function canWriteStorageKey(user, key) {
  if (user.is_master) return true;
  return !(key === "agrimill-purchases" && user.department_id === "production")
    && canReadStorageKey(user, key);
}

function getAccessibleDomains(user) {
  if (user.is_master) return ["inventory", "stores"];
  const modules = departmentModules[user.department_id] || [];
  return [
    ...(modules.includes("inventory") ? ["inventory"] : []),
    ...(modules.includes("stores") ? ["stores"] : [])
  ];
}

function productDomain(item) {
  const category = String(item?.category || "").trim().toLowerCase();
  if (["packaging", "spare parts", "consumables"].includes(category)) return "stores";
  if (["raw material", "finished goods", "by-product"].includes(category)
    || ["paddy", "rice", "by-product", "byproduct"].includes(category)
    || /\b(paddy|rice|byproducts?)\b/i.test(item?.name || "")) return "inventory";
  return "stores";
}

function parseStorageArray(value, status = 500) {
  let records;
  try {
    records = JSON.parse(value);
  } catch (error) {
    if (status === 400) throw new HttpError(400, "Submitted department data is not a valid record list.");
    console.error("Could not parse stored department data.", error);
    throw new HttpError(500, "Stored department data is not a valid record list.");
  }
  if (!Array.isArray(records)) {
    const message = status === 400
      ? "Submitted department data is not a valid record list."
      : "Stored department data is not a valid record list.";
    throw new HttpError(status, message);
  }
  return records;
}

async function getAllInventoryItems() {
  const row = await get("SELECT value FROM storage WHERE key = 'agrimill-inventory-items'");
  return row ? parseStorageArray(row.value) : [];
}

function getStorageRecordDomain(key, record, inventoryItems) {
  if (key === "agrimill-inventory-items") return productDomain(record);
  if (key === "agrimill-stockMovement") {
    const item = inventoryItems.find(candidate => candidate.sku === record[3]);
    return productDomain(item || { name: record[4] });
  }
  if (key === "agrimill-inventory-purchases") {
    const item = inventoryItems.find(candidate => candidate.sku === record[3]);
    return productDomain(item || { name: record[4], category: record[5] });
  }
  return null;
}

async function filterStorageValue(user, key, value) {
  if (user.department_id === "production" && key === "agrimill-purchases") {
    return JSON.stringify(parseStorageArray(value).map(record => {
      const visibleRecord = [...record];
      visibleRecord[1] = "—";
      visibleRecord[3] = "—";
      return visibleRecord;
    }));
  }
  if (user.is_master || !["agrimill-inventory-items", "agrimill-stockMovement", "agrimill-inventory-purchases"].includes(key)) {
    return value;
  }
  const domains = getAccessibleDomains(user);
  const items = key === "agrimill-inventory-items" ? [] : await getAllInventoryItems();
  const records = parseStorageArray(value);
  const visible = [];
  for (const record of records) {
    if (domains.includes(getStorageRecordDomain(key, record, items))) visible.push(record);
  }
  return JSON.stringify(visible);
}

async function mergeStorageValue(user, key, value) {
  if (user.is_master || !["agrimill-inventory-items", "agrimill-stockMovement", "agrimill-inventory-purchases"].includes(key)) {
    return value;
  }
  const domains = getAccessibleDomains(user);
  const currentRow = await get("SELECT value FROM storage WHERE key = ?", [key]);
  const existing = currentRow ? parseStorageArray(currentRow.value) : [];
  const incoming = parseStorageArray(value, 400);
  const items = key === "agrimill-inventory-items" ? [] : await getAllInventoryItems();
  const merged = [];
  for (const record of existing) {
    if (!domains.includes(getStorageRecordDomain(key, record, items))) merged.push(record);
  }
  for (const record of incoming) {
    if (domains.includes(getStorageRecordDomain(key, record, items))) merged.push(record);
  }
  return JSON.stringify(merged);
}

async function deleteStorageKey(user, key) {
  if (user.is_master || !["agrimill-inventory-items", "agrimill-stockMovement", "agrimill-inventory-purchases"].includes(key)) {
    await run("DELETE FROM storage WHERE key = ?", [key]);
    return;
  }
  const row = await get("SELECT value FROM storage WHERE key = ?", [key]);
  if (!row) return;
  const domains = getAccessibleDomains(user);
  const items = key === "agrimill-inventory-items" ? [] : await getAllInventoryItems();
  const remaining = [];
  for (const record of parseStorageArray(row.value)) {
    if (!domains.includes(getStorageRecordDomain(key, record, items))) remaining.push(record);
  }
  if (remaining.length) {
    await run("UPDATE storage SET value = ? WHERE key = ?", [JSON.stringify(remaining), key]);
  } else {
    await run("DELETE FROM storage WHERE key = ?", [key]);
  }
}

async function initializeDatabase() {
  await run("CREATE TABLE IF NOT EXISTS storage (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
  await run(`CREATE TABLE IF NOT EXISTS auth_users (
    user_id TEXT PRIMARY KEY COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    department_id TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 0,
    is_master INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
  )`);
  await run("CREATE INDEX IF NOT EXISTS auth_sessions_user_id_idx ON auth_sessions(user_id)");
  await run("CREATE UNIQUE INDEX IF NOT EXISTS auth_users_single_master_idx ON auth_users(is_master) WHERE is_master = 1");
  const userColumns = await all("PRAGMA table_info(auth_users)");
  if (!userColumns.some(column => column.name === "must_change_password")) {
    await run("ALTER TABLE auth_users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0");
  }
  const legacyOtpTable = await get("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'auth_otps'");
  const existingMaster = legacyOtpTable && await get("SELECT user_id FROM auth_users WHERE is_master = 1");
  if (existingMaster) {
    const credentials = await hashPassword(getInitialAdminPassword());
    await run(
      "UPDATE auth_users SET password_salt = ?, password_hash = ?, must_change_password = 1 WHERE user_id = ?",
      [credentials.salt, credentials.hash, existingMaster.user_id]
    );
    await run("DELETE FROM auth_sessions WHERE user_id = ?", [existingMaster.user_id]);
  }
  await run("UPDATE auth_users SET email = lower(user_id) || '@account.invalid', email_verified = 1");
  await run("DROP TABLE IF EXISTS auth_otps");
  await run("DELETE FROM storage WHERE key = 'agrimill-user'");
  await run("DELETE FROM auth_sessions WHERE expires_at <= ?", [Date.now()]);
}

app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use("/api", (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.get("/app.js", (_req, res) => res.sendFile(path.join(__dirname, "app.js")));
app.get("/styles.css", (_req, res) => res.sendFile(path.join(__dirname, "styles.css")));
app.get("/api/health", (_req, res) => res.json({ ok: true, service: "agrimill-erp-backend" }));

app.get("/api/auth/session", asyncRoute(async (_req, res) => {
  const master = await get("SELECT 1 FROM auth_users WHERE is_master = 1");
  const token = cookieValue(_req, sessionCookie);
  let user = null;
  if (token && /^[a-f0-9]{64}$/.test(token)) {
    user = await get(
      `SELECT u.user_id, u.name, u.department_id, u.is_master, u.must_change_password
       FROM auth_sessions s JOIN auth_users u ON u.user_id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_active = 1`,
      [crypto.createHash("sha256").update(token).digest("hex"), Date.now()]
    );
    if (!user) clearSessionCookie(res);
  }
  res.json({ initialized: Boolean(master), user: user ? publicUser(user) : null });
}));

app.post("/api/auth/bootstrap", asyncRoute(async (req, res) => {
  requireRateLimit(`bootstrap-ip:${req.ip}`, 5, 10 * 60 * 1000);
  const master = await get("SELECT 1 FROM auth_users WHERE is_master = 1");
  if (master) throw new HttpError(409, "The administrator account has already been created.");
  const initialPassword = getInitialAdminPassword();
  const submittedPassword = typeof req.body?.initialPassword === "string" ? req.body.initialPassword : "";
  const expected = Buffer.from(initialPassword);
  const submitted = Buffer.from(submittedPassword);
  if (expected.length !== submitted.length || !crypto.timingSafeEqual(expected, submitted)) {
    throw new HttpError(401, "The initial administrator password is incorrect.");
  }
  const credentials = await hashPassword(initialPassword);
  try {
    await run(
      `INSERT INTO auth_users
        (user_id, email, name, department_id, password_salt, password_hash, email_verified, is_active, is_master, must_change_password, created_at)
       VALUES (?, ?, ?, 'admin', ?, ?, 1, 1, 1, 1, ?)`,
      [masterUserId, `${masterUserId}@account.invalid`, "Sachin Agarwal", credentials.salt, credentials.hash, Date.now()]
    );
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT") throw new HttpError(409, "The administrator account has already been created.");
    throw error;
  }
  const user = await get("SELECT user_id, name, department_id, is_master, must_change_password FROM auth_users WHERE is_master = 1");
  res.json({ ok: true, user: await createSession(res, user) });
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const userId = typeof req.body?.userId === "string" ? req.body.userId.trim() : "";
  const password = req.body?.password;
  if (!userId || userId.length > 64 || typeof password !== "string" || password.length > 128) {
    throw new HttpError(400, "Enter a valid user ID and password.");
  }
  requireRateLimit(`login-ip:${req.ip}`, 60, 10 * 60 * 1000);
  requireRateLimit(`login:${req.ip}:${userId.toLowerCase()}`, 10, 10 * 60 * 1000);
  const user = await get(
    "SELECT user_id, name, department_id, password_salt, password_hash, is_master, must_change_password FROM auth_users WHERE user_id = ? AND is_active = 1",
    [userId]
  );
  if (!user || typeof password !== "string" || !await verifyPassword(password, user.password_salt, user.password_hash)) {
    throw new HttpError(401, "User ID or password is incorrect.");
  }
  res.json({ ok: true, user: await createSession(res, user) });
}));

app.post("/api/auth/password/change", requireUser, asyncRoute(async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  validatePassword(newPassword);
  const user = await get(
    "SELECT user_id, password_salt, password_hash FROM auth_users WHERE user_id = ? AND is_active = 1",
    [req.user.user_id]
  );
  if (!user || typeof currentPassword !== "string"
    || !await verifyPassword(currentPassword, user.password_salt, user.password_hash)) {
    throw new HttpError(401, "Current password is incorrect.");
  }

  const credentials = await hashPassword(newPassword);
  await run(
    "UPDATE auth_users SET password_salt = ?, password_hash = ?, must_change_password = 0 WHERE user_id = ?",
    [credentials.salt, credentials.hash, user.user_id]
  );
  const updatedUser = await get(
    "SELECT user_id, name, department_id, is_master, must_change_password FROM auth_users WHERE user_id = ?",
    [user.user_id]
  );
  await run("DELETE FROM auth_sessions WHERE user_id = ? AND token_hash != ?", [
    user.user_id,
    crypto.createHash("sha256").update(cookieValue(req, sessionCookie)).digest("hex")
  ]);
  res.json({ ok: true, user: publicUser(updatedUser) });
}));

app.post("/api/auth/logout", asyncRoute(async (req, res) => {
  const token = cookieValue(req, sessionCookie);
  if (/^[a-f0-9]{64}$/.test(token)) {
    await run("DELETE FROM auth_sessions WHERE token_hash = ?", [
      crypto.createHash("sha256").update(token).digest("hex")
    ]);
  }
  clearSessionCookie(res);
  res.json({ ok: true });
}));

app.get("/api/admin/users", requireUser, requireAdmin, asyncRoute(async (_req, res) => {
  const users = await all(
    `SELECT user_id AS userId, name, department_id AS departmentId, is_active AS isActive,
      must_change_password AS mustChangePassword, created_at AS createdAt
     FROM auth_users WHERE is_master = 0 ORDER BY created_at DESC`
  );
  res.json({ users: users.map(user => ({
    ...user,
    isActive: Boolean(user.isActive),
    mustChangePassword: Boolean(user.mustChangePassword),
    role: departmentLabels[user.departmentId]
  })) });
}));

app.post("/api/admin/users", requireUser, requireAdmin, asyncRoute(async (req, res) => {
  const userId = typeof req.body?.userId === "string" ? req.body.userId.trim() : "";
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  const departmentId = req.body?.departmentId;
  const temporaryPassword = req.body?.temporaryPassword;
  if (!/^[a-zA-Z0-9._-]{3,48}$/.test(userId)) {
    throw new HttpError(400, "User ID must be 3–48 characters and use letters, numbers, dots, underscores, or hyphens.");
  }
  validatePassword(temporaryPassword);
  if (!name || name.length > 100) throw new HttpError(400, "Enter a name of up to 100 characters.");
  if (!Object.hasOwn(departmentModules, departmentId) || departmentId === "admin") {
    throw new HttpError(400, "Choose a valid non-administrator department.");
  }
  const credentials = await hashPassword(temporaryPassword);
  const existing = await get("SELECT is_active FROM auth_users WHERE user_id = ?", [userId]);
  try {
    if (existing?.is_active) throw new HttpError(409, "That user ID already belongs to an active account.");
    if (existing) {
      await run(
        `UPDATE auth_users SET email = ?, name = ?, department_id = ?, password_salt = ?, password_hash = ?,
          email_verified = 1, is_active = 1, must_change_password = 1 WHERE user_id = ?`,
        [`${userId.toLowerCase()}@account.invalid`, name, departmentId, credentials.salt, credentials.hash, userId]
      );
    } else {
      await run(
        `INSERT INTO auth_users
          (user_id, email, name, department_id, password_salt, password_hash, email_verified, is_active, is_master, must_change_password, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 1, 1, 0, 1, ?)`,
        [userId, `${userId.toLowerCase()}@account.invalid`, name, departmentId, credentials.salt, credentials.hash, Date.now()]
      );
    }
  } catch (error) {
    if (error instanceof HttpError) throw error;
    if (error.code === "SQLITE_CONSTRAINT") throw new HttpError(409, "That user ID is already in use.");
    throw error;
  }
  await run("DELETE FROM auth_sessions WHERE user_id = ?", [userId]);
  res.status(existing ? 200 : 201).json({
    ok: true,
    message: `Account ready. Share the temporary password securely with ${userId}; they must change it at first sign-in.`
  });
}));

app.post("/api/admin/users/:userId/reset-password", requireUser, requireAdmin, asyncRoute(async (req, res) => {
  const temporaryPassword = req.body?.temporaryPassword;
  validatePassword(temporaryPassword);
  const user = await get("SELECT user_id FROM auth_users WHERE user_id = ? AND is_master = 0", [req.params.userId]);
  if (!user) throw new HttpError(404, "Staff account not found.");
  const credentials = await hashPassword(temporaryPassword);
  await run(
    `UPDATE auth_users SET password_salt = ?, password_hash = ?, email_verified = 1,
      is_active = 1, must_change_password = 1 WHERE user_id = ?`,
    [credentials.salt, credentials.hash, user.user_id]
  );
  await run("DELETE FROM auth_sessions WHERE user_id = ?", [user.user_id]);
  res.json({ ok: true, message: `Temporary password set for ${user.user_id}. Share it securely; they must change it at first sign-in.` });
}));

app.patch("/api/admin/users/:userId/status", requireUser, requireAdmin, asyncRoute(async (req, res) => {
  const active = req.body?.active;
  if (typeof active !== "boolean") throw new HttpError(400, "An active status is required.");
  const user = await get("SELECT user_id FROM auth_users WHERE user_id = ? AND is_master = 0", [req.params.userId]);
  if (!user) throw new HttpError(404, "Staff account not found.");
  await run("UPDATE auth_users SET is_active = ? WHERE user_id = ?", [active ? 1 : 0, user.user_id]);
  if (!active) await run("DELETE FROM auth_sessions WHERE user_id = ?", [user.user_id]);
  res.json({ ok: true });
}));

app.delete("/api/admin/users/:userId", requireUser, requireAdmin, asyncRoute(async (req, res) => {
  const user = await get("SELECT user_id FROM auth_users WHERE user_id = ? AND is_master = 0", [req.params.userId]);
  if (!user) throw new HttpError(404, "Staff account not found.");
  await run("DELETE FROM auth_sessions WHERE user_id = ?", [user.user_id]);
  await run("DELETE FROM auth_users WHERE user_id = ?", [user.user_id]);
  res.json({ ok: true });
}));

app.get("/api/storage", requireUser, asyncRoute(async (req, res) => {
  const key = typeof req.query.key === "string" ? req.query.key : null;
  if (key) {
    if (!canReadStorageKey(req.user, key)) throw new HttpError(403, "You do not have access to this department's data.");
    const row = await get("SELECT value FROM storage WHERE key = ?", [key]);
    res.json({ key, value: row ? await filterStorageValue(req.user, key, row.value) : null });
    return;
  }

  const rows = await all("SELECT key, value FROM storage ORDER BY key");
  const payload = {};
  for (const row of rows) {
    if (canReadStorageKey(req.user, row.key)) {
      payload[row.key] = await filterStorageValue(req.user, row.key, row.value);
    }
  }
  res.json(payload);
}));

app.post("/api/storage", requireUser, asyncRoute(async (req, res) => {
  const { key, value } = req.body || {};
  if (typeof key !== "string" || key.trim() === "") throw new HttpError(400, "A non-empty string key is required.");
  if (key.length > 128 || key === "agrimill-user") throw new HttpError(400, "Invalid storage key.");
  if (!canWriteStorageKey(req.user, key)) throw new HttpError(403, "You do not have access to change this department's data.");
  const submitted = typeof value === "string" ? value : JSON.stringify(value);
  const serialized = await mergeStorageValue(req.user, key, submitted);
  await run(
    "INSERT INTO storage (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    [key, serialized]
  );
  res.json({ ok: true, key, value: serialized });
}));

app.delete("/api/storage", requireUser, asyncRoute(async (req, res) => {
  const { key } = req.body || req.query || {};
  if (typeof key === "string" && key.trim() !== "") {
    if (!canWriteStorageKey(req.user, key)) throw new HttpError(403, "You do not have access to change this department's data.");
    await deleteStorageKey(req.user, key);
    res.json({ ok: true, key, removed: true });
    return;
  }
  if (req.user.is_master) {
    await run("DELETE FROM storage");
  } else {
    const rows = await all("SELECT key FROM storage");
    for (const row of rows) {
      if (canWriteStorageKey(req.user, row.key)) await deleteStorageKey(req.user, row.key);
    }
  }
  res.json({ ok: true, cleared: true });
}));

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  res.sendFile(path.join(__dirname, "index.html"), error => {
    if (error) next(error);
  });
});

app.use((error, _req, res, _next) => {
  if (error instanceof HttpError) {
    res.status(error.status).json({ error: error.message });
    return;
  }
  console.error("Request failed.", error);
  res.status(500).json({ error: "An unexpected server error occurred." });
});

initializeDatabase().then(() => {
  app.listen(port, () => {
    console.log(`Backend running on port ${port}`);
  });
}).catch(error => {
  console.error("Could not initialize the database.", error);
  process.exit(1);
});
