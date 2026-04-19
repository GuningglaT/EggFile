'use strict';
const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, dialog } = require('electron');
const path    = require('path');
const fs      = require('fs');
const http    = require('http');
const https   = require('https');
const crypto  = require('crypto');
const { spawn }  = require('child_process');
const { Worker } = require('worker_threads');
const { v4: uuidv4 } = require('uuid');
const mqtt    = require('mqtt');

// ── Constantes ───────────────────────────────────────────────────────────────
const IS_PORTABLE = fs.existsSync(path.join(path.dirname(app.getPath('exe')), 'eggfile-portable'));
const BASE_DATA_DIR = IS_PORTABLE ? path.join(path.dirname(app.getPath('exe')), 'data') : path.join(app.getPath('userData'), 'eggfile');

const DATA_DIR   = BASE_DATA_DIR;
const DB_FILE    = path.join(DATA_DIR, 'data.json');
const ICON_PATH  = path.join(__dirname, '..', 'assets', 'icon.png');
const ICON_ICO   = path.join(__dirname, '..', 'assets', 'icon.ico');

// Priorizar cloudflared.exe en la carpeta de la app para distribución embebida
const LOCAL_CF   = path.join(path.dirname(app.getPath('exe')), 'cloudflared.exe');
const CF_PATH    = fs.existsSync(LOCAL_CF) ? LOCAL_CF : path.join(DATA_DIR, 'cloudflared.exe');

const CF_DL_URL  = 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe';
const ZIP_WORKER = path.join(__dirname, 'zip-worker.js');

const MQTT_BROKER       = 'wss://broker.hivemq.com:8884/mqtt';
const MQTT_PREFIX       = 'eggfile/v1';
const HEARTBEAT_MS      = 30 * 1000;
const HEARTBEAT_TIMEOUT = 10 * 1000;
const RETRY_BASE_MS     = 10 * 1000;   // backoff exponencial: base 10s
const RETRY_MAX_MS      = 5 * 60 * 1000;
const REQUEST_TTL_MS    = 5 * 60 * 1000;
const UPDATE_CHECK_URL  = 'https://raw.githubusercontent.com/ruffg/eggfile-app/main/version.json';
const CURRENT_VERSION   = app.getVersion();
const RATE_LIMIT_MAX    = 60;          // max requests por minuto por IP
const RATE_LIMIT_DL_MAX = 5;          // max descargas simultáneas
const RATE_LIMIT_ID_MAX = 30;         // max requests por minuto por friendId (previene bypass con NAT)
const RATE_LIMIT_ROUTE_MAX = 20;      // max requests por minuto por (friendId+routeId) — previene abuso por ruta
const ZIP_WORKER_MAX    = 2;          // max workers ZIP concurrentes
const CLOCK_DRIFT_MS    = 30 * 1000;  // tolerancia de clock drift: 30s adicionales sobre TTL
const FAMILY_INVITE_TTL      = 48 * 60 * 60 * 1000; // invitaciones de familia expiran en 48h
const FRIEND_REQUEST_TTL     = 7 * 24 * 60 * 60 * 1000; // solicitudes de amistad expiran en 7 días
const FAMILY_MQTT_RATE_MAX   = 10;  // max eventos de familia por minuto por emisor
const FAMILY_SYNC_RETRY_DELAYS = [0, 1000, 3000, 10000]; // backoff para sync HTTP
const LOG_MAX_SIZE_BYTES = 5 * 1024 * 1024; // 5MB — rotar logs que superen este tamaño

// ── Config de recursos — defaults (el usuario puede sobreescribir desde Ajustes) ──
const DEFAULT_RESOURCE_CONFIG = {
  maxActiveDownloads: 5,
  maxZipWorkers: 2,
  maxZipSizeGB: 10,
  maxBrowseItems: 500,
  maxBandwidthMBps: 50,
  rateLimitPerMinute: 60,
  rateLimitPerFriend: 30,
  rateLimitPerRoute: 20,
};

function getResourceConfig() {
  const db = readDB();
  const saved = db?.resourceConfig || {};
  return { ...DEFAULT_RESOURCE_CONFIG, ...saved };
}

// ── Estado global ─────────────────────────────────────────────────────────────
let mainWindow     = null;
let tray           = null;
let p2pServer      = null;
let p2pPort        = 0;
let cfProcess      = null;
let tunnelUrl      = null;
let mqttClient     = null;
let heartbeatTimer = null;
let tunnelStatus   = 'connecting';

const friendStatus  = {};
let retryInterval   = null;
let retryAttempt    = 0;

// Nonce store — guarda nonces usados para evitar replay attacks dentro de la ventana TTL
const usedNonces = new Map(); // nonce -> expiry timestamp

// Rate limiter — requests por IP por minuto
const rateLimitMap   = new Map(); // ip -> { count, resetAt }
const rateLimitIdMap = new Map(); // friendId -> { count, resetAt }  ← previene bypass por NAT
const rateLimitRouteMap = new Map(); // `${friendId}:${routeId}` -> { count, resetAt } ← por ruta
let activeDownloads  = 0; // Descargas entrantes (que yo sirvo)
let activeOutgoingDownloads = 0; // Descargas salientes (que yo bajo de otros)
let outgoingQueue = [];
let downloadHistory = []; // Para mostrar completados
let activeZipWorkers = 0;
const zipQueue       = [];

const { Transform } = require('stream');
class ThrottleStream extends Transform {
  constructor(mbps) {
    super();
    this.bytesPerSecond = mbps * 1024 * 1024;
    this.bucket = this.bytesPerSecond;
    this.lastCheck = Date.now();
  }
  _transform(chunk, encoding, callback) {
    const now = Date.now();
    const elapsed = (now - this.lastCheck) / 1000;
    this.bucket += elapsed * this.bytesPerSecond;
    if (this.bucket > this.bytesPerSecond) this.bucket = this.bytesPerSecond;
    this.lastCheck = now;

    if (chunk.length <= this.bucket) {
      this.bucket -= chunk.length;
      this.push(chunk);
      callback();
    } else {
      const waitTime = ((chunk.length - this.bucket) / this.bytesPerSecond) * 1000;
      this.bucket = 0;
      this.push(chunk);
      setTimeout(callback, waitTime);
    }
  }
}

// Security log — intentos fallidos y eventos de seguridad
const SEC_LOG_FILE = path.join(DATA_DIR, 'security.log');

// MQTT rate limit por familia/emisor — previene flood de eventos de familia
const mqttFamilyRateMap = new Map(); // `${fromId}:${familyId}` -> { count, resetAt }

// Rate limit para solicitudes de amistad — previene spam de requests
const friendRequestRateMap = new Map(); // fromId -> { count, resetAt }

// Retry tracking para sync de familia — { familyId -> { attempt, timer } }
const familySyncRetryMap = new Map();
function secLog(event, detail = '') {
  try {
    ensureDataDir();
    const ts = new Date().toISOString();
    const line = `${ts} [${event}] ${detail}\n`;
    fs.appendFileSync(SEC_LOG_FILE, line);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('activity:new', { type: 'sec', ts, event, detail, raw: line });
    }
  } catch {}
}

// Access log — accesos exitosos: quién descargó qué, cuándo y cuántos bytes
const ACCESS_LOG_FILE = path.join(DATA_DIR, 'access.log');
function accessLog(action, friendId, detail = '') {
  try {
    ensureDataDir();
    const db      = readDB();
    const friend  = (db?.friends || []).find(f => f.id === friendId);
    const name    = friend?.username || friendId.slice(0, 8);
    const alias   = friend?.alias;
    const display = alias ? `${alias} (${name})` : name;
    const ts      = new Date().toISOString();
    const line    = `${ts} [${action}] friend=${display} ${detail}\n`;
    fs.appendFileSync(ACCESS_LOG_FILE, line);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('activity:new', { type: 'access', ts, action, display, detail, raw: line });
    }
  } catch {}
}

// ── DB ────────────────────────────────────────────────────────────────────────
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}
function readDB() {
  ensureDataDir();
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return null; }
}
function writeDB(data) {
  ensureDataDir();
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// ── Seguridad ─────────────────────────────────────────────────────────────────
// Par de claves ECDH — generado una sola vez, persiste en DB
// La clave privada se guarda cifrada con safeStorage (DPAPI en Windows)
function ensureECDHKeys(db) {
  if (db.ecdhPublic) {
    // Intentar recuperar clave privada de safeStorage
    const priv = loadPrivateKey();
    if (priv) { db.ecdhPrivate = priv; return db; }
    // Fallback: clave en DB (menos seguro pero compatible)
    if (db.ecdhPrivate) return db;
  }
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  db.ecdhPrivate = ecdh.getPrivateKey('hex');
  db.ecdhPublic  = ecdh.getPublicKey('hex', 'uncompressed');
  // Guardar en safeStorage si está disponible, sino en DB como fallback
  if (!savePrivateKey(db.ecdhPrivate)) {
    // safeStorage no disponible — clave queda en DB
    console.warn('[SEC] safeStorage no disponible, clave privada en DB');
  } else {
    // Borrar de DB si estaba, safeStorage es más seguro
    delete db.ecdhPrivate;
  }
  writeDB(db);
  // Para uso inmediato devolvemos con la clave en memoria
  db.ecdhPrivate = ecdh.getPrivateKey('hex');
  return db;
}

// Deriva la clave compartida con ECDH+HKDF — una sola vez al agregar amigo
function deriveSharedKey(myPrivateHex, friendPublicHex) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(myPrivateHex, 'hex'));
  const secret = ecdh.computeSecret(Buffer.from(friendPublicHex, 'hex'));
  return crypto.hkdfSync('sha256', secret, Buffer.alloc(0), Buffer.from('eggfile-v1'), 32).toString('hex');
}

function getSharedKey(friendId) {
  const db = readDB();
  if (!db?.sharedKeys) return null;
  return db.sharedKeys[friendId] || null;
}

// HMAC-SHA256 con timestamp + nonce — evita falsificación y replay attacks
function signPayload(payload, ts, nonce, sharedKey) {
  return crypto.createHmac('sha256', sharedKey).update(`${payload}:${ts}:${nonce}`).digest('hex');
}

function verifySignature(payload, ts, nonce, sig, sharedKey) {
  if (!sharedKey || !sig || !ts || !nonce) return false;
  // Clock drift: ventana = TTL + tolerancia de drift
  if (Math.abs(Date.now() - parseInt(ts)) > REQUEST_TTL_MS + CLOCK_DRIFT_MS) return false;
  if (!checkAndStoreNonce(nonce)) return false; // replay attack
  const expected = signPayload(payload, ts, nonce, sharedKey);
  try { return crypto.timingSafeEqual(Buffer.from(expected,'hex'), Buffer.from(sig,'hex')); }
  catch { return false; }
}

// AES-256-GCM para cifrar payloads MQTT
function encryptMQTT(plaintext, sharedKey) {
  const key    = Buffer.from(sharedKey, 'hex').slice(0, 32);
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return JSON.stringify({ iv: iv.toString('hex'), tag: tag.toString('hex'), data: enc.toString('hex') });
}

function decryptMQTT(ciphertext, sharedKey) {
  const { iv, tag, data } = JSON.parse(ciphertext);
  const key      = Buffer.from(sharedKey, 'hex').slice(0, 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return decipher.update(Buffer.from(data, 'hex')) + decipher.final('utf8');
}

// ── Nonce — anti-replay dentro de la ventana TTL ─────────────────────────────
function generateNonce() { return crypto.randomBytes(16).toString('hex'); }

function checkAndStoreNonce(nonce) {
  if (!nonce) return false;
  // Limpiar nonces expirados
  const now = Date.now();
  for (const [n, exp] of usedNonces) { if (exp < now) usedNonces.delete(n); }
  if (usedNonces.has(nonce)) return false; // ya usado → replay attack
  usedNonces.set(nonce, now + REQUEST_TTL_MS);
  return true;
}

// Rate limiter por IP
function checkRateLimit(ip) {
  const now    = Date.now();
  const entry  = rateLimitMap.get(ip);
  if (!entry || entry.resetAt < now) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + 60000, violations: 0 });
    return true;
  }
  if (entry.count >= getResourceConfig().rateLimitPerMinute) {
    entry.violations = (entry.violations || 0) + 1;
    const penalty = Math.min(entry.violations * 60000, 30 * 60000); // Max 30 min
    entry.resetAt = now + penalty;
    return false;
  }
  entry.count++;
  return true;
}

// Rate limiter por friendId — previene bypass con NAT compartido o rotación de IP
function checkRateLimitId(friendId) {
  const now   = Date.now();
  const entry = rateLimitIdMap.get(friendId);
  if (!entry || entry.resetAt < now) {
    rateLimitIdMap.set(friendId, { count: 1, resetAt: now + 60000, violations: 0 });
    return true;
  }
  if (entry.count >= getResourceConfig().rateLimitPerFriend) {
    entry.violations = (entry.violations || 0) + 1;
    const penalty = Math.min(entry.violations * 60000, 30 * 60000);
    entry.resetAt = now + penalty;
    return false;
  }
  entry.count++;
  return true;
}

// Rate limiter por ruta — previene que un amigo abuse de una ruta específica
function checkRateLimitRoute(friendId, routeId) {
  if (!routeId) return true;
  const key   = `${friendId}:${routeId}`;
  const now   = Date.now();
  const entry = rateLimitRouteMap.get(key);
  if (!entry || entry.resetAt < now) {
    rateLimitRouteMap.set(key, { count: 1, resetAt: now + 60000, violations: 0 });
    return true;
  }
  if (entry.count >= getResourceConfig().rateLimitPerRoute) {
    entry.violations = (entry.violations || 0) + 1;
    const penalty = Math.min(entry.violations * 60000, 30 * 60000);
    entry.resetAt = now + penalty;
    return false;
  }
  entry.count++;
  return true;
}

// Rate limiter para eventos MQTT de familia — previene flood por emisor+familia
function checkFamilyMqttRateLimit(fromId, familyId) {
  const key  = `${fromId}:${familyId}`;
  const now  = Date.now();
  const entry = mqttFamilyRateMap.get(key);
  if (!entry || entry.resetAt < now) {
    mqttFamilyRateMap.set(key, { count: 1, resetAt: now + 60000 });
    return true;
  }
  if (entry.count >= FAMILY_MQTT_RATE_MAX) {
    secLog('FAMILY_MQTT_RATE_LIMIT', `fromId=${fromId} familyId=${familyId}`);
    return false;
  }
  entry.count++;
  return true;
}

// Rate limiter para solicitudes de amistad — max 5 requests por remitente por hora
function checkFriendRequestRateLimit(fromId) {
  const now   = Date.now();
  const entry = friendRequestRateMap.get(fromId);
  if (!entry || entry.resetAt < now) {
    friendRequestRateMap.set(fromId, { count: 1, resetAt: now + 60 * 60 * 1000 });
    return true;
  }
  if (entry.count >= 5) {
    secLog('FRIEND_REQUEST_RATE_LIMIT', `fromId=${fromId}`);
    return false;
  }
  entry.count++;
  return true;
}

// ── Safe storage — clave privada ECDH cifrada con DPAPI via safeStorage ───────
function savePrivateKey(privHex) {
  try {
    if (!app.isReady() || !require('electron').safeStorage.isEncryptionAvailable()) return false;
    const enc = require('electron').safeStorage.encryptString(privHex);
    fs.writeFileSync(path.join(DATA_DIR, 'privkey.enc'), enc);
    return true;
  } catch { return false; }
}

function loadPrivateKey() {
  try {
    const encPath = path.join(DATA_DIR, 'privkey.enc');
    if (!fs.existsSync(encPath)) return null;
    const enc = fs.readFileSync(encPath);
    return require('electron').safeStorage.decryptString(enc);
  } catch { return null; }
}

// ── Fingerprint — SHA-256 de la clave pública para verificación manual ────────
function getFingerprint(pubKeyHex) {
  const hash = crypto.createHash('sha256').update(Buffer.from(pubKeyHex, 'hex')).digest('hex');
  // Formato legible: grupos de 4 separados por ':'
  return hash.match(/.{1,4}/g).join(':').toUpperCase().slice(0, 47);
}

// ── Autostart ─────────────────────────────────────────────────────────────────
function setLoginItem(enable) {
  app.setLoginItemSettings({
    openAtLogin: enable,
    path: app.isPackaged ? process.execPath : undefined,
    args: app.isPackaged ? [] : [path.resolve(process.argv[1])],
  });
}
function getLoginItem() { return app.getLoginItemSettings().openAtLogin; }

// ── Ventana ───────────────────────────────────────────────────────────────────
function createWindow() {
  const iconFile = fs.existsSync(ICON_ICO) ? ICON_ICO : (fs.existsSync(ICON_PATH) ? ICON_PATH : null);
  const icon = iconFile ? nativeImage.createFromPath(iconFile) : undefined;
  mainWindow = new BrowserWindow({
    width: 1100, height: 720, minWidth: 800, minHeight: 560,
    frame: false, backgroundColor: '#0d0d0f', icon,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false },
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWindow.on('close', e => { e.preventDefault(); mainWindow.hide(); });
  
  // Verificar actualizaciones al iniciar (delay para no entorpecer)
  setTimeout(() => checkUpdates(), 10000);
}

// ── Tray ──────────────────────────────────────────────────────────────────────
function createTray() {
  const iconFile = fs.existsSync(ICON_ICO) ? ICON_ICO : (fs.existsSync(ICON_PATH) ? ICON_PATH : null);
  const icon = iconFile ? nativeImage.createFromPath(iconFile).resize({ width:16, height:16 }) : nativeImage.createEmpty();
  tray = new Tray(icon);
  tray.setToolTip('EggFile P2P');
  
  const updateMenu = () => {
    const d = readDB();
    const myId = d ? d.id : 'No autenticado';
    const statusText = tunnelStatus === 'ready' ? 'Online (Túnel)' : (tunnelStatus === 'error' ? 'Error' : 'Conectando...');
    
    const contextMenu = Menu.buildFromTemplate([
      { label: 'EggFile P2P', enabled: false },
      { type: 'separator' },
      { label: `Estado: ${statusText}`, enabled: false },
      { label: `ID: ${myId}`, enabled: false },
      { label: 'Copiar ID', click: () => {
          if (d && d.id) {
            require('electron').clipboard.writeText(d.id);
            if (mainWindow) mainWindow.webContents.send('toast', { msg: 'ID copiado al portapapeles', type: 'success' });
          }
        }
      },
      { type: 'separator' },
      { label: 'Abrir Aplicación', click: () => mainWindow.show() },
      { label: 'Salir', click: () => { stopHeartbeat(); stopMQTT(); killTunnel(); app.exit(0); } },
    ]);
    tray.setContextMenu(contextMenu);
  };

  updateMenu();
  tray.on('double-click', () => mainWindow.show());
  
  // Actualizar menú periódicamente para reflejar cambios de estado
  setInterval(updateMenu, 5000);
}

// ── Updates ──────────────────────────────────────────────────────────────────
async function checkUpdates(manual = false) {
  try {
    const res = await httpGetWithTimeout(UPDATE_CHECK_URL, 5000);
    const info = JSON.parse(res);
    if (info.version && info.version !== CURRENT_VERSION) {
      const choice = dialog.showMessageBoxSync(mainWindow, {
        type: 'info',
        buttons: ['Descargar', 'Más tarde'],
        title: 'Nueva actualización',
        message: `Hay una nueva versión disponible: ${info.version}`,
        detail: info.notes || 'Se recomienda actualizar para obtener las últimas mejoras.'
      });
      if (choice === 0) require('electron').shell.openExternal(info.url || 'https://github.com/ruffg/eggfile-app/releases');
    } else if (manual) {
      dialog.showMessageBoxSync(mainWindow, { type: 'info', message: 'Tenés la última versión instalada.' });
    }
  } catch (e) {
    if (manual) dialog.showMessageBoxSync(mainWindow, { type: 'error', message: 'No se pudo verificar la actualización.' });
  }
}

// ── Cloudflare Tunnel ─────────────────────────────────────────────────────────
function downloadCloudflared() {
  return new Promise((resolve, reject) => {
    ensureDataDir();
    if (fs.existsSync(CF_PATH)) { resolve(); return; }
    const file   = fs.createWriteStream(CF_PATH);
    const follow = (url, depth = 0) => {
      if (depth > 10) { reject(new Error('Demasiadas redirecciones')); return; }
      const mod = url.startsWith('https') ? https : http;
      mod.get(url, { headers: { 'User-Agent': 'EggFile/1.0' } }, res => {
        if ([301,302,307,308].includes(res.statusCode)) { follow(res.headers.location, depth+1); }
        else if (res.statusCode === 200) { res.pipe(file); file.on('finish', () => file.close(resolve)); file.on('error', reject); }
        else { reject(new Error('HTTP ' + res.statusCode)); }
      }).on('error', reject);
    };
    follow(CF_DL_URL);
  });
}

function startTunnel(port) {
  return new Promise((resolve) => {
    if (cfProcess) { resolve(tunnelUrl); return; }
    const launch = () => {
      cfProcess = spawn(CF_PATH, ['tunnel', '--url', `http://localhost:${port}`, '--no-autoupdate'], { windowsHide: true });
      let resolved = false;
      const done = (url) => { if (!resolved) { resolved = true; tunnelUrl = url; resolve(url); } };
      cfProcess.stderr.on('data', chunk => {
        const match = chunk.toString().match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
        if (match) done(match[0]);
      });
      cfProcess.on('error', err => { console.error('[CF] Error spawn:', err.message); done(null); });
      cfProcess.on('exit', () => { cfProcess = null; tunnelUrl = null; setTunnelStatus('down'); stopHeartbeat(); });
      setTimeout(() => done(null), 30000);
    };
    downloadCloudflared().then(launch).catch(err => {
      console.error('[CF] Descarga fallida:', err.message);
      setTunnelStatus('down');
      resolve(null);
      // Reintentar descarga si falló
      setTimeout(() => startTunnel(port), 60000);
    });
  });
}

function killTunnel() {
  stopHeartbeat();
  if (cfProcess) { cfProcess.kill(); cfProcess = null; tunnelUrl = null; }
}

// ── Heartbeat — detección activa del estado del túnel ────────────────────────
function setTunnelStatus(status) {
  if (tunnelStatus === status) return;
  tunnelStatus = status;
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('tunnel:status', { status, url: tunnelUrl });
}

function startHeartbeat() {
  stopHeartbeat();
  heartbeatTimer = setInterval(async () => {
    if (!tunnelUrl) {
      if (cfProcess) return; // Esperando a que el proceso levante
      setTunnelStatus('down');
      // Intentar levantar de nuevo si tenemos puerto
      if (p2pPort && !cfProcess) startP2PServer(); 
      return;
    }
    const start = Date.now();
    try {
      await httpGetWithTimeout(`${tunnelUrl}/info`, HEARTBEAT_TIMEOUT);
      setTunnelStatus(Date.now() - start > 8000 ? 'throttled' : 'online');
      heartbeatFails = 0;
    } catch (err) {
      const msg = (err.message || '').toLowerCase();
      if (msg.includes('timeout') || msg.includes('reset') || msg.includes('403') || msg.includes('404')) {
        setTunnelStatus('blocked');
        heartbeatFails++;
        if (heartbeatFails > 3) {
          heartbeatFails = 0;
          secLog('TUNNEL_RESTART_TRIGGERED', `Reason: ${msg}`);
          killTunnel();
        }
      } else {
        setTunnelStatus('down');
      }
    }
  }, HEARTBEAT_MS);
}

function stopHeartbeat() {
  if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
}

function httpGetWithTimeout(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: timeoutMs }, res => { res.resume(); res.statusCode < 500 ? resolve(res.statusCode) : reject(new Error('HTTP '+res.statusCode)); });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

// ── Reenviar solicitudes de amistad no enviadas por estar offline ─────────────
function republishPendingFriendRequests() {
  const db = readDB();
  if (!db || !mqttClient?.connected) return;
  const now = Date.now();
  for (const req of (db.sentFriendRequests || [])) {
    if (req.expiresAt < now) continue;
    // No reenviar si ya es amigo
    if ((db.friends || []).find(f => f.id === req.toId)) continue;
    try {
      mqttClient.publish(
        `${MQTT_PREFIX}/${req.toId}`,
        JSON.stringify({ type: 'friend_request', fromId: db.id, fromUsername: db.username, fromPubKey: db.ecdhPublic }),
        { qos: 1 }
      );
    } catch {}
  }
}

// ── MQTT ──────────────────────────────────────────────────────────────────────
function startMQTT() {
  const db = readDB();
  if (!db || mqttClient) return;
  mqttClient = mqtt.connect(MQTT_BROKER, { clientId: `eggfile_${db.id}_${Date.now()}`, clean: true, reconnectPeriod: 5000 });
  mqttClient.on('connect', () => {
    mqttClient.subscribe(`${MQTT_PREFIX}/${db.id}`, { qos: 1 });
    if (tunnelUrl) publishTunnelUrl(tunnelUrl);
    syncAllFamiliesOnConnect();
    // Reenviar solicitudes de amistad pendientes que no pudieron enviarse offline
    republishPendingFriendRequests();
  });
  mqttClient.on('message', (topic, message) => {
    try {
      const envelope = JSON.parse(message.toString());
      const d        = readDB();

      // ── Solicitud de amistad — llega SIN cifrar (primer contacto, no hay sharedKey) ──
      if (envelope.type === 'friend_request') {
        handleFriendRequest(envelope, d);
        return;
      }

      // ── Respuesta a solicitud de amistad — llega cifrada con la sharedKey ──
      if (envelope.type === 'friend_request_accepted') {
        handleFriendRequestAccepted(envelope, d);
        return;
      }

      const friend   = (d.friends || []).find(f => f.id === envelope.fromId);
      if (!friend) return;
      const sharedKey = getSharedKey(envelope.fromId);
      if (!sharedKey) return;
      const msg = JSON.parse(decryptMQTT(envelope.enc, sharedKey));
      if (msg.type === 'tunnel_update') {
        friend.tunnelUrl = msg.tunnelUrl;
        writeDB(d);
        friendStatus[friend.id] = { online: true, lastSeen: Date.now() };
        notifyFriendStatusChange();
        if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('friends:tunnelUpdated', { friendId: friend.id });
      } else if (msg.type === 'family_invite') {
        handleFamilyInvite(msg, friend, d);
      } else if (msg.type === 'family_invite_response') {
        handleFamilyInviteResponse(msg, friend, d);
      } else if (msg.type === 'family_removed') {
        handleFamilyRemoved(msg, friend, d);
      } else if (msg.type === 'family_updated') {
        handleFamilyUpdated(msg, friend, d);
      } else if (msg.type === 'search_request') {
        handleSearchRequest(msg, friend, d);
      } else if (msg.type === 'search_response') {
        handleSearchResponse(msg, friend, d);
      } else if (msg.type === 'family_chat') {
        handleFamilyChat(msg, friend, d);
      }
    } catch (e) { console.error('[MQTT] Error:', e.message); }
  });
  mqttClient.on('error', err => console.error('[MQTT] Error:', err.message));
}

function publishTunnelUrl(url) {
  const db = readDB();
  if (!db || !mqttClient?.connected) return;
  for (const friend of (db.friends || [])) {
    const sharedKey = getSharedKey(friend.id);
    if (!sharedKey) continue;
    try {
      const enc      = encryptMQTT(JSON.stringify({ type: 'tunnel_update', tunnelUrl: url }), sharedKey);
      mqttClient.publish(`${MQTT_PREFIX}/${friend.id}`, JSON.stringify({ fromId: db.id, enc }), { qos: 1 });
    } catch {}
  }
}

function stopMQTT() { if (mqttClient) { mqttClient.end(true); mqttClient = null; } }

function handleFamilyChat(msg, friend, db) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('family:chatMessage', {
      familyId: msg.familyId,
      fromId: friend.id,
      fromUsername: friend.username,
      text: msg.text,
      ts: msg.ts || Date.now()
    });
  }
}

function handleFamilyUpdated(msg, friend, db) {
  // El owner de una familia notifica un cambio de estado — hacemos sync pull
  const family = (db.families || []).find(f => f.id === msg.familyId && f.ownerId === msg.fromId);
  if (!family || !friend.tunnelUrl) return;
  // Validación estricta de versiones — ignorar estado viejo
  if (msg.version && msg.version <= (family.version || 0)) {
    secLog('FAMILY_STALE_VERSION', `familyId=${msg.familyId} incoming=${msg.version} local=${family.version}`);
    return;
  }
  // Rate limit ya verificado en publishFamilyEvent del remitente, pero checkeamos aquí también
  if (!checkFamilyMqttRateLimit(msg.fromId, msg.familyId)) return;
  // Pull asíncrono con retry — no bloqueamos el handler
  syncFamilyFromOwnerWithRetry(family, friend.tunnelUrl, db.id);
}

// ── Búsqueda Global MQTT ──────────────────────────────────────────────────
function handleSearchRequest(msg, friend, db) {
  const query = msg.query || '';
  if (query.length < 3) return;
  const results = [];
  for (const route of (db.routes || [])) {
    if (!fs.existsSync(route.path)) continue;
    // Solo buscar en rutas compartidas con este amigo (o públicas/familias)
    if (!resolveAllowedFriends(route, db).has(msg.fromId)) continue;
    walkSearch(route.path, route.path, route.id, route.name, query.toLowerCase(), results, 0);
  }
  // Enviar respuesta
  publishFamilyEvent(msg.fromId, 'search_response', { requestId: msg.requestId, results });
}

function walkSearch(basePath, currentDir, routeId, routeName, query, results, depth) {
  if (depth > 6 || results.length > 40) return;
  try {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const e of entries) {
      if (e.name.toLowerCase().includes(query)) {
        const rel = path.relative(basePath, path.join(currentDir, e.name)).replace(/\\/g, '/');
        results.push({
          name: e.name,
          type: e.isDirectory() ? 'dir' : 'file',
          routeId,
          routeName,
          relPath: rel
        });
      }
      if (e.isDirectory()) {
        walkSearch(basePath, path.join(currentDir, e.name), routeId, routeName, query, results, depth + 1);
      }
      if (results.length > 40) break;
    }
  } catch {}
}

function handleSearchResponse(msg, friend, db) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('p2p:searchResult', {
      fromId: friend.id,
      fromUsername: friend.username,
      requestId: msg.requestId,
      results: msg.results || []
    });
  }
}

// ── Familia MQTT — publicar evento cifrado a un amigo concreto ────────────
function publishFamilyEvent(toFriendId, type, payload) {
  const db = readDB();
  if (!db || !mqttClient?.connected) return;
  const sharedKey = getSharedKey(toFriendId);
  if (!sharedKey) return;
  // Rate limit por emisor+familia
  const famId = payload?.familyId || '';
  if (!checkFamilyMqttRateLimit(db.id, famId)) return;
  try {
    const enc = encryptMQTT(JSON.stringify({ type, fromId: db.id, ...payload }), sharedKey);
    mqttClient.publish(`${MQTT_PREFIX}/${toFriendId}`, JSON.stringify({ fromId: db.id, enc }), { qos: 1 });
  } catch (e) { console.error('[MQTT family]', e.message); }
}

// ── Familia MQTT — handlers de eventos entrantes ──────────────────────────
function handleFamilyInvite(msg, friend, db) {
  // Guardar invitación pendiente en DB para que la UI la muestre
  if (!msg.familyId || !msg.familyName) return;
  if (!db.pendingFamilyInvites) db.pendingFamilyInvites = [];
  // Evitar duplicados
  const exists = db.pendingFamilyInvites.find(i => i.familyId === msg.familyId && i.fromId === msg.fromId);
  if (exists) return;
  db.pendingFamilyInvites.push({
    familyId: msg.familyId,
    familyName: msg.familyName,
    fromId: msg.fromId,
    fromUsername: friend.username,
    receivedAt: Date.now(),
    expiresAt: msg.expiresAt || (Date.now() + FAMILY_INVITE_TTL),
  });
  writeDB(db);
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('families:inviteReceived', { familyId: msg.familyId, familyName: msg.familyName, fromUsername: friend.username });
}

function handleFamilyInviteResponse(msg, friend, db) {
  // Owner recibe respuesta de un invitado
  const family = (db.families || []).find(f => f.id === msg.familyId && f.ownerId === db.id);
  if (!family) return;
  // Limpiar pendingInvites
  if (family.pendingInvites) family.pendingInvites = family.pendingInvites.filter(i => i.toId !== msg.fromId);
  if (msg.accepted) {
    if (!family.memberIds.includes(msg.fromId)) {
      family.memberIds.push(msg.fromId);
      family.version = (family.version || 0) + 1;
    }
    writeDB(db);
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('families:memberJoined', { familyId: msg.familyId, memberId: msg.fromId, username: friend.username });
  } else {
    writeDB(db);
  }
  secLog('FAMILY_INVITE_RESPONSE', `familyId=${msg.familyId} fromId=${msg.fromId} accepted=${!!msg.accepted}`);
}

function handleFamilyRemoved(msg, friend, db) {
  // Fui expulsado de una familia, o un miembro me notifica que salió
  if (!msg.familyId) return;
  const idx = (db.families || []).findIndex(f => f.id === msg.familyId);
  if (idx === -1) return;
  const family = db.families[idx];
  // Si el fromId es el owner y yo soy miembro → me expulsaron
  if (family.ownerId === msg.fromId && family.role === 'member') {
    db.families.splice(idx, 1);
    writeDB(db);
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('families:removedFromFamily', { familyId: msg.familyId, familyName: family.name });
  }
  // Si soy owner y fromId era miembro → salida voluntaria
  if (family.ownerId === db.id) {
    family.memberIds = family.memberIds.filter(id => id !== msg.fromId);
    family.version = (family.version || 0) + 1;
    writeDB(db);
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('families:memberLeft', { familyId: msg.familyId, memberId: msg.fromId });
  }
}

// ── Solicitudes de amistad ────────────────────────────────────────────────────
//
// Flujo:
//  1. A pega el ID de B → A envía friend_request (sin cifrar) al topic MQTT de B
//  2. B recibe la notificación, ve la solicitud, la acepta
//  3. Al aceptar, B agrega a A, deriva la sharedKey, y envía friend_request_accepted
//     (cifrado con la sharedKey recién derivada) al topic MQTT de A
//  4. A recibe la respuesta, agrega a B, deriva la sharedKey, y publica su tunnelUrl
//
// El mensaje friend_request va sin cifrar porque es el PRIMER contacto — no existe
// sharedKey todavía. Cualquiera que conozca el topic puede verlo, pero no puede
// falsificar la pubKey (sería inútil porque B aceptaría manualmente).

function handleFriendRequest(envelope, db) {
  // Validar campos mínimos
  if (!envelope.fromId || !envelope.fromUsername || !envelope.fromPubKey) return;
  if (typeof envelope.fromId !== 'string' || typeof envelope.fromUsername !== 'string') return;

  // Rate limit — prevenir spam
  if (!checkFriendRequestRateLimit(envelope.fromId)) return;

  // No procesar solicitudes propias
  if (envelope.fromId === db?.id) return;

  // Ignorar si ya es amigo
  if ((db?.friends || []).find(f => f.id === envelope.fromId)) return;

  // Evitar duplicados en pendientes
  if (!db.pendingFriendRequests) db.pendingFriendRequests = [];
  const exists = db.pendingFriendRequests.find(r => r.fromId === envelope.fromId);
  if (exists) return;

  const request = {
    fromId:       envelope.fromId,
    fromUsername: envelope.fromUsername,
    fromPubKey:   envelope.fromPubKey,
    receivedAt:   Date.now(),
    expiresAt:    Date.now() + FRIEND_REQUEST_TTL,
  };

  db.pendingFriendRequests.push(request);
  writeDB(db);

  secLog('FRIEND_REQUEST_RECEIVED', `fromId=${envelope.fromId} fromUsername=${envelope.fromUsername}`);
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('friends:requestReceived', {
      fromId:       request.fromId,
      fromUsername: request.fromUsername,
    });
  }
}

function handleFriendRequestAccepted(envelope, db) {
  // Este mensaje llega cifrado — necesitamos la sharedKey
  // Como A aún no tiene a B como amigo, la sharedKey aún no existe.
  // La derivamos temporalmente con la pubKey del envelope para descifrar.
  if (!envelope.fromId || !envelope.fromPubKey || !envelope.enc) return;

  try {
    // Derivar sharedKey temporal con la pubKey del que acepta
    const myPrivate = db.ecdhPrivate || loadPrivateKey();
    if (!myPrivate) return;
    const tempKey = deriveSharedKey(myPrivate, envelope.fromPubKey);
    const msg     = JSON.parse(decryptMQTT(envelope.enc, tempKey));

    if (msg.type !== 'friend_request_accepted') return;
    if (msg.fromId !== envelope.fromId) return;

    // Verificar que nosotros le habíamos enviado la solicitud
    if (!db.sentFriendRequests) return;
    const sent = db.sentFriendRequests.find(r => r.toId === envelope.fromId);
    if (!sent) return;

    // Agregar como amigo
    if ((db.friends || []).find(f => f.id === envelope.fromId)) return; // ya existe

    if (!db.sharedKeys) db.sharedKeys = {};
    db.sharedKeys[envelope.fromId] = tempKey;

    if (!db.friends) db.friends = [];
    db.friends.push({
      id:        envelope.fromId,
      username:  msg.fromUsername || envelope.fromId.slice(0, 8),
      pubKey:    envelope.fromPubKey,
      tunnelUrl: msg.tunnelUrl || null,
      addedAt:   Date.now(),
    });

    // Limpiar solicitud enviada
    db.sentFriendRequests = db.sentFriendRequests.filter(r => r.toId !== envelope.fromId);
    writeDB(db);

    // Publicar nuestra tunnelUrl al nuevo amigo
    if (tunnelUrl && mqttClient?.connected) {
      try {
        const enc = encryptMQTT(JSON.stringify({ type: 'tunnel_update', tunnelUrl }), tempKey);
        mqttClient.publish(`${MQTT_PREFIX}/${envelope.fromId}`, JSON.stringify({ fromId: db.id, enc }), { qos: 1 });
      } catch {}
    }

    friendStatus[envelope.fromId] = { online: msg.tunnelUrl ? true : false, lastSeen: Date.now() };
    notifyFriendStatusChange();
    secLog('FRIEND_REQUEST_ACCEPTED', `fromId=${envelope.fromId}`);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('friends:requestAccepted', {
        friendId:  envelope.fromId,
        username:  msg.fromUsername || envelope.fromId.slice(0, 8),
      });
    }
  } catch (e) {
    secLog('FRIEND_REQUEST_ACCEPTED_ERROR', `fromId=${envelope.fromId} err=${e.message}`);
  }
}

// ── Sync de familia — pull desde el owner ────────────────────────────────
async function syncFamilyFromOwner(family, ownerTunnelUrl, myId) {
  const sharedKey = getSharedKey(family.ownerId);
  if (!sharedKey) return;
  const base  = normalizeAddress(ownerTunnelUrl);
  const ts    = Date.now().toString();
  const nonce = generateNonce();
  const sig   = signPayload(`/family-sync:${myId}`, ts, nonce, sharedKey);
  const url   = `${base}/family-sync?familyId=${encodeURIComponent(family.id)}&friendId=${encodeURIComponent(myId)}&ts=${ts}&nonce=${nonce}&sig=${sig}`;
  const raw   = await httpGetAny(url);
  const state = JSON.parse(raw);
  if (!state.id) return;
  const db = readDB();
  const idx = (db.families || []).findIndex(f => f.id === state.id);
  if (idx === -1) {
    // Nueva familia que no teníamos (caso: se aceptó en otro dispositivo)
    if (!db.families) db.families = [];
    db.families.push({ ...state, role: 'member', isSynced: true, ownerSharedRoutes: state.mySharedRoutes || [] });
  } else {
    // Validación estricta: solo actualizar si la versión remota es mayor
    if ((state.version || 0) <= (db.families[idx].version || 0)) return;
    const myIdIsStillMember = (state.memberIds || []).some(m => (typeof m === 'string' ? m : m.id) === db.id);
    if (!myIdIsStillMember) {
      // Fui expulsado (llegó offline) — borrar familia
      const famName = db.families[idx].name;
      db.families.splice(idx, 1);
      writeDB(db);
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('families:removedFromFamily', { familyId: state.id, familyName: famName });
      return;
    }
    db.families[idx] = { ...db.families[idx], memberIds: state.memberIds, version: state.version, name: state.name, ownerSharedRoutes: state.mySharedRoutes || [], isSynced: true };
  }
  writeDB(db);
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('families:synced', { familyId: state.id });
}

// ── Sync con retry y backoff ──────────────────────────────────────────────
function syncFamilyFromOwnerWithRetry(family, ownerTunnelUrl, myId, attemptIndex = 0) {
  const delay = FAMILY_SYNC_RETRY_DELAYS[attemptIndex] ?? null;
  if (delay === null) {
    // Máximo de reintentos alcanzado — marcar como no sincronizado
    const db = readDB();
    if (!db) return;
    const idx = (db.families || []).findIndex(f => f.id === family.id);
    if (idx !== -1) { db.families[idx].isSynced = false; writeDB(db); }
    secLog('FAMILY_SYNC_MAX_RETRIES', `familyId=${family.id}`);
    return;
  }

  // Cancelar retry previo si lo había
  const existing = familySyncRetryMap.get(family.id);
  if (existing?.timer) clearTimeout(existing.timer);

  const timer = setTimeout(async () => {
    familySyncRetryMap.delete(family.id);
    try {
      await syncFamilyFromOwner(family, ownerTunnelUrl, myId);
    } catch (e) {
      console.error(`[FAMILY SYNC] retry ${attemptIndex}:`, e.message);
      syncFamilyFromOwnerWithRetry(family, ownerTunnelUrl, myId, attemptIndex + 1);
    }
  }, delay);

  familySyncRetryMap.set(family.id, { attempt: attemptIndex, timer });
}

// ── Sync de todas las familias al reconectar ──────────────────────────────
async function syncAllFamiliesOnConnect() {
  const db = readDB();
  if (!db) return;
  for (const family of (db.families || [])) {
    if (family.role !== 'member' || !family.ownerId) continue;
    const owner = (db.friends || []).find(f => f.id === family.ownerId);
    if (!owner?.tunnelUrl) continue;
    // Usar versión con retry y backoff
    syncFamilyFromOwnerWithRetry(family, owner.tunnelUrl, db.id, 0);
  }
}

// ── Sync state ────────────────────────────────────────────────────────────────
function notifyFriendStatusChange() {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('friends:statusUpdate', friendStatus);
}

async function syncTunnelToFriends(myNewUrl) {
  const db = readDB();
  if (!db || !myNewUrl) return;
  for (const friend of (db.friends || [])) {
    if (!friend.tunnelUrl) continue;
    const sharedKey = getSharedKey(friend.id);
    if (!sharedKey) continue;
    try {
      const ts      = Date.now().toString();
      const nonce   = generateNonce();
      const payload = JSON.stringify({ type: 'tunnel_update', fromId: db.id, tunnelUrl: myNewUrl, localIp: getLocalIp(), port: p2pPort });
      const sig     = signPayload(payload, ts, nonce, sharedKey);
      await httpPostJSON(`${friend.tunnelUrl}/message`, { payload, ts, nonce, sig, fromId: db.id });
      friendStatus[friend.id] = { online: true, lastSeen: Date.now() };
    } catch {
      friendStatus[friend.id] = { online: false, lastSeen: friendStatus[friend.id]?.lastSeen || null };
    }
  }
  notifyFriendStatusChange();
}

function startRetrySync() {
  if (retryInterval) return;
  const scheduleNext = () => {
    const delay = Math.min(RETRY_BASE_MS * Math.pow(2, retryAttempt), RETRY_MAX_MS);
    retryInterval = setTimeout(async () => {
      retryInterval = null;
      const db = readDB();
      if (!db || !tunnelUrl) return;
      let anyOffline = false;
      for (const friend of (db.friends || [])) {
        if (!friend.tunnelUrl || friendStatus[friend.id]?.online) continue;
        anyOffline = true;
        const sharedKey = getSharedKey(friend.id);
        if (!sharedKey) continue;
        try {
          const ts      = Date.now().toString();
          const nonce   = generateNonce();
          const payload = JSON.stringify({ type: 'tunnel_update', fromId: db.id, tunnelUrl, localIp: getLocalIp(), port: p2pPort });
          const sig     = signPayload(payload, ts, nonce, sharedKey);
          await httpPostJSON(`${friend.tunnelUrl}/message`, { payload, ts, nonce, sig, fromId: db.id });
          friendStatus[friend.id] = { online: true, lastSeen: Date.now() };
          notifyFriendStatusChange();
        } catch {}
      }
      if (anyOffline) { retryAttempt++; scheduleNext(); }
      else { retryAttempt = 0; }
    }, delay);
  };
  scheduleNext();
}

// ── Monitor de Amigos (Latencia y LAN) ───────────────────────────────────────
let friendMonitorTimer = null;
function startFriendMonitor() {
  if (friendMonitorTimer) clearInterval(friendMonitorTimer);
  friendMonitorTimer = setInterval(async () => {
    const db = readDB();
    if (!db) return;
    for (const friend of (db.friends || [])) {
      const st = friendStatus[friend.id];
      if (!st) continue;
      
      let targetUrl = friend.tunnelUrl;
      let isLan = false;
      
      // Intentar LAN si tenemos localIp
      if (friend.localIp && friend.port) {
        const lanUrl = `http://${friend.localIp}:${friend.port}`;
        try {
          const start = Date.now();
          await httpGetWithTimeout(`${lanUrl}/info`, 1000);
          targetUrl = lanUrl;
          isLan = true;
          st.latencyMs = Date.now() - start;
          st.online = true;
        } catch {
          // Si LAN falla, seguimos con el túnel
        }
      }
      
      // Si no es LAN o falló, probar túnel
      if (!isLan && friend.tunnelUrl) {
        try {
          const start = Date.now();
          await httpGetWithTimeout(`${friend.tunnelUrl}/info`, 3000);
          st.latencyMs = Date.now() - start;
          st.online = true;
        } catch {
          st.online = false;
        }
      }
      st.isLan = isLan;
      st.effectiveUrl = targetUrl;
    }
    notifyFriendStatusChange();
  }, 10000); // Cada 10s
}

async function notifyFriendsBeforeQuit() {
  const db = readDB();
  if (!db) return;
  const promises = (db.friends || []).filter(f => f.tunnelUrl && friendStatus[f.id]?.online).map(f => {
    const sharedKey = getSharedKey(f.id);
    if (!sharedKey) return Promise.resolve();
    const ts      = Date.now().toString();
    const nonce   = generateNonce();
    const payload = JSON.stringify({ type: 'going_offline', fromId: db.id });
    const sig     = signPayload(payload, ts, nonce, sharedKey);
    return httpPostJSON(`${f.tunnelUrl}/message`, { payload, ts, nonce, sig, fromId: db.id }).catch(() => {});
  });
  await Promise.allSettled(promises);
}

// ── Resolver acceso efectivo de una ruta ─────────────────────────────────────
// Combina allowedFriends explícitos + miembros de familias asociadas a la ruta.
// Usado en todos los endpoints del servidor P2P para verificar acceso.
// ── UPnP: Apertura automática de puertos ─────────────────────────────────────
function mapPortUPnP(port) {
  const dgram = require('dgram');
  const client = dgram.createSocket('udp4');
  const msg = Buffer.from(
    'M-SEARCH * HTTP/1.1\r\n' +
    'HOST: 239.255.255.250:1900\r\n' +
    'MAN: "ssdp:discover"\r\n' +
    'MX: 2\r\n' +
    'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n'
  );

  client.on('message', (data, info) => {
    const raw = data.toString();
    const match = raw.match(/LOCATION: (http:\/\/[^\s]+)/i);
    if (match) {
      const location = match[1];
      client.close();
      tryToMap(location, port);
    }
  });

  client.send(msg, 0, msg.length, 1900, '239.255.255.250');
  setTimeout(() => { try { client.close(); } catch{} }, 5000);
}

async function tryToMap(location, port) {
  try {
    const desc = await httpGetAny(location);
    const match = desc.match(/<controlURL>(.+?)<\/controlURL>/i); // Simplificado
    if (!match) return;
    let ctrl = match[1];
    if (!ctrl.startsWith('http')) {
      const base = new URL(location);
      ctrl = `${base.protocol}//${base.host}${ctrl.startsWith('/') ? '' : '/'}${ctrl}`;
    }

    const localIp = getLocalIp();
    const soap = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>${port}</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewInternalPort>${port}</NewInternalPort>
      <NewInternalClient>${localIp}</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>EggFile P2P</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>`;

    const url = require('url').parse(ctrl);
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request({
      ...url,
      method: 'POST',
      headers: {
        'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
        'Content-Type': 'text/xml; charset="utf-8"',
        'Content-Length': Buffer.byteLength(soap)
      }
    });
    req.write(soap);
    req.end();
    secLog('UPNP_MAPPED', `port=${port} router=${url.host}`);
  } catch (e) {
    console.error('[UPnP] Fail:', e.message);
  }
}

function resolveAllowedFriends(route, db) {
  const ids = new Set(route.allowedFriends || []);
  for (const familyId of (route.familyIds || [])) {
    const family = (db.families || []).find(f => f.id === familyId);
    if (family) family.memberIds.forEach(id => ids.add(id));
  }
  return ids;
}

// ── P2P Server ────────────────────────────────────────────────────────────────
function startP2PServer() {
  if (p2pServer) return;
  const db = readDB();
  if (!db) return;

  p2pServer = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const p   = url.pathname;
    res.setHeader('Access-Control-Allow-Origin', '*');

    function validateHMAC() {
      const ip       = req.socket?.remoteAddress || 'unknown';
      if (!checkRateLimit(ip)) {
        secLog('RATE_LIMIT_IP', `ip=${ip} path=${p}`);
        return null;
      }
      const friendId = url.searchParams.get('friendId') || '';
      const ts       = url.searchParams.get('ts')       || '';
      const nonce    = url.searchParams.get('nonce')    || '';
      const sig      = url.searchParams.get('sig')      || '';
      if (!friendId || !ts || !nonce || !sig) {
        secLog('MISSING_AUTH_PARAMS', `ip=${ip} path=${p}`);
        return null;
      }
      if (!checkRateLimitId(friendId)) {
        secLog('RATE_LIMIT_ID', `friendId=${friendId} ip=${ip} path=${p}`);
        return null;
      }
      const sharedKey = getSharedKey(friendId);
      if (!sharedKey) {
        secLog('UNKNOWN_FRIEND', `friendId=${friendId} ip=${ip}`);
        return null;
      }
      const d = readDB();
      const friend = (d.friends || []).find(f => f.id === friendId);
      if (!friend) {
        secLog('UNKNOWN_FRIEND', `friendId=${friendId} ip=${ip}`);
        return null;
      }
      if (!verifySignature(`${p}:${friendId}`, ts, nonce, sig, sharedKey)) {
        secLog('INVALID_SIG', `friendId=${friendId} ip=${ip} path=${p}`);
        return null;
      }
      return { friend, db: d };
    }

    if (p === '/info') {
      const d = readDB();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ username: d.username, id: d.id, pubKey: d.ecdhPublic }));
      return;
    }

    if (p === '/routes') {
      const auth = validateHMAC();
      if (!auth) { res.writeHead(403); res.end('No autorizado'); return; }
      const friendId   = url.searchParams.get('friendId') || '';
      const accessible = (auth.db.routes || []).filter(r => resolveAllowedFriends(r, auth.db).has(friendId)).map(r => ({ id: r.id, name: r.name }));
      const sharedKey  = getSharedKey(friendId);
      const payload    = JSON.stringify({ routes: accessible });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (sharedKey) {
        res.end(JSON.stringify({ enc: encryptMQTT(payload, sharedKey) }));
      } else {
        res.end(payload);
      }
      return;
    }

    if (p === '/browse') {
      const auth = validateHMAC();
      if (!auth) { res.writeHead(403); res.end('No autorizado'); return; }
      const routeId  = url.searchParams.get('routeId') || '';
      const subPath  = url.searchParams.get('path')    || '';
      const friendId = url.searchParams.get('friendId')|| '';
      const route    = (auth.db.routes || []).find(r => r.id === routeId);
      if (!route || !resolveAllowedFriends(route, auth.db).has(friendId)) { res.writeHead(403); res.end('Acceso denegado'); return; }
      if (!checkRateLimitRoute(friendId, routeId)) {
        secLog('RATE_LIMIT_ROUTE', `friendId=${friendId} routeId=${routeId} path=${subPath}`);
        res.writeHead(429); res.end('Límite por ruta excedido'); return;
      }
      const target = subPath ? path.join(route.path, subPath) : route.path;
      if (!target.startsWith(route.path)) { res.writeHead(403); res.end('Acceso denegado'); return; }
      try {
        const entries = fs.readdirSync(target, { withFileTypes: true });
        const items   = entries.map(e => {
          const full = path.join(target, e.name); const isDir = e.isDirectory(); let size = null;
          if (!isDir) { try { size = fs.statSync(full).size; } catch {} }
          return { name: e.name, type: isDir?'dir':'file', ext: path.extname(e.name).slice(1).toLowerCase(), size, sizeStr: isDir?null:formatBytes(size) };
        });
        items.sort((a,b) => a.type!==b.type?(a.type==='dir'?-1:1):a.name.localeCompare(b.name,'es',{sensitivity:'base'}));
        const maxItems = getResourceConfig().maxBrowseItems;
        const truncated = items.length > maxItems;
        if (truncated) items.length = maxItems;
        accessLog('BROWSE', friendId, `routeId=${routeId} route=${route.name} path=${subPath||'/'} items=${items.length}${truncated ? ' (truncated)' : ''}`);
        const sharedKey = getSharedKey(friendId);
        const payload   = JSON.stringify({ items, truncated });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (sharedKey) {
          res.end(JSON.stringify({ enc: encryptMQTT(payload, sharedKey) }));
        } else {
          res.end(payload);
        }
      } catch (e) { res.writeHead(500); res.end(e.message); }
      return;
    }

    if (p === '/download') {
      const auth = validateHMAC();
      if (!auth) { res.writeHead(403); res.end('No autorizado'); return; }
      if (activeDownloads >= getResourceConfig().maxActiveDownloads) { res.writeHead(429); res.end('Demasiadas descargas simultáneas'); return; }
      const routeId  = url.searchParams.get('routeId') || '';
      const filePath = url.searchParams.get('path')    || '';
      const friendId = url.searchParams.get('friendId')|| '';
      const route    = (auth.db.routes || []).find(r => r.id === routeId);
      if (!route || !resolveAllowedFriends(route, auth.db).has(friendId)) { res.writeHead(403); res.end('Acceso denegado'); return; }
      if (!checkRateLimitRoute(friendId, routeId)) {
        secLog('RATE_LIMIT_ROUTE', `friendId=${friendId} routeId=${routeId} path=${filePath}`);
        res.writeHead(429); res.end('Límite por ruta excedido'); return;
      }
      const target = path.resolve(path.join(route.path, filePath));
      if (!target.startsWith(path.resolve(route.path))) { res.writeHead(403); res.end('Acceso denegado'); return; }
      if (!fs.existsSync(target)) { res.writeHead(404); res.end('No encontrado'); return; }

      let stat;
      try { stat = fs.statSync(target); }
      catch (e) { res.writeHead(500); res.end('Error al acceder al archivo'); return; }

      const range = req.headers.range;
      let stream;
      let released = false;
      const releaseDownload = () => { if (!released) { released = true; activeDownloads--; } };

      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end   = parts[1] ? parseInt(parts[1], 10) : stat.size - 1;
        if (start >= stat.size) {
          res.writeHead(416, { 'Content-Range': `bytes */${stat.size}` });
          return res.end();
        }
        const chunksize = (end - start) + 1;
        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${stat.size}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunksize,
          'Content-Type': 'application/octet-stream',
        });
        stream = fs.createReadStream(target, { start, end });
        accessLog('DOWNLOAD_RANGE', friendId, `routeId=${routeId} file=${path.basename(target)} range=${start}-${end}/${stat.size}`);
      } else {
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${encodeURIComponent(path.basename(target))}"`,
          'Content-Length': stat.size,
          'Accept-Ranges': 'bytes',
        });
        stream = fs.createReadStream(target);
        accessLog('DOWNLOAD', friendId, `routeId=${routeId} route=${route.name} file=${path.basename(target)} size=${stat.size}`);
      }

      activeDownloads++;
      stream.on('error', err => {
        releaseDownload();
        secLog('DOWNLOAD_ERROR', `friendId=${friendId} file=${target} err=${err.message}`);
        res.destroy();
      });
      stream.on('end',  releaseDownload);
      res.on('close',   releaseDownload);

      const config = getResourceConfig();
      if (config.maxBandwidthMBps > 0) {
        stream.pipe(new ThrottleStream(config.maxBandwidthMBps)).pipe(res);
      } else {
        stream.pipe(res);
      }
      return;
    }

    if (p === '/folder-size') {
      const auth = validateHMAC();
      if (!auth) { res.writeHead(403); res.end('No autorizado'); return; }
      const routeId  = url.searchParams.get('routeId') || '';
      const subPath  = url.searchParams.get('path')    || '';
      const friendId = url.searchParams.get('friendId')|| '';
      const route    = (auth.db.routes || []).find(r => r.id === routeId);
      if (!route || !resolveAllowedFriends(route, auth.db).has(friendId)) { res.writeHead(403); res.end('Acceso denegado'); return; }
      const target = subPath ? path.join(route.path, subPath) : route.path;
      if (!target.startsWith(route.path)) { res.writeHead(403); res.end('Acceso denegado'); return; }
      const bytes = getDirSize(target);
      accessLog('FOLDER_SIZE', friendId, `routeId=${routeId} route=${route.name} path=${subPath||'/'} size=${bytes}`);
      const sharedKey = getSharedKey(friendId);
      const payload   = JSON.stringify({ bytes, sizeStr: formatBytes(bytes) });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (sharedKey) {
        res.end(JSON.stringify({ enc: encryptMQTT(payload, sharedKey) }));
      } else {
        res.end(payload);
      }
      return;
    }

    if (p === '/family-sync') {
      const auth = validateHMAC();
      if (!auth) { res.writeHead(403); res.end('No autorizado'); return; }
      const familyId = url.searchParams.get('familyId') || '';
      const d = readDB();
      // Solo el owner puede responder datos de su familia
      const family = (d.families || []).find(f => f.id === familyId && f.ownerId === d.id);
      if (!family) { res.writeHead(404); res.end('Familia no encontrada'); return; }
      // Verificar que el solicitante es miembro activo
      const friendId = url.searchParams.get('friendId') || '';
      const isMember = (family.memberIds || []).some(m => (typeof m === 'string' ? m : m.id) === friendId);
      // Construir las rutas que YO (owner) publiqué en esta familia
      const mySharedRoutes = (d.routes || [])
        .filter(r => (r.familyIds || []).includes(familyId))
        .map(r => ({ id: r.id, name: r.name, ownerId: d.id }));
      const safeFamily = {
        id:           family.id,
        name:         family.name,
        ownerId:      family.ownerId,
        memberIds:    isMember ? (family.memberIds || []) : [],
        version:      family.version || 0,
        mySharedRoutes, // rutas que el owner publicó en esta familia
      };
      const sharedKey = getSharedKey(friendId);
      const payload   = JSON.stringify(safeFamily);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (sharedKey) {
        res.end(JSON.stringify({ enc: encryptMQTT(payload, sharedKey) }));
      } else {
        res.end(payload);
      }
      return;
    }

    // Endpoint: obtener las rutas que un miembro compartió en una familia
    if (p === '/family-member-routes') {
      const auth = validateHMAC();
      if (!auth) { res.writeHead(403); res.end('No autorizado'); return; }
      const familyId = url.searchParams.get('familyId') || '';
      const friendId = url.searchParams.get('friendId') || '';
      const d = readDB();
      // Verificar que yo soy miembro de esta familia
      const family = (d.families || []).find(f => f.id === familyId);
      if (!family) { res.writeHead(404); res.end('Familia no encontrada'); return; }
      const isMember = (family.memberIds || []).some(m => (typeof m === 'string' ? m : m.id) === friendId)
        || family.ownerId === friendId;
      if (!isMember) { res.writeHead(403); res.end('No sos miembro de esta familia'); return; }
      // Devolver las rutas que YO publiqué en esta familia
      const myRoutes = (d.routes || [])
        .filter(r => (r.familyIds || []).includes(familyId))
        .map(r => ({ id: r.id, name: r.name, ownerId: d.id }));
      const sharedKey = getSharedKey(friendId);
      const payload   = JSON.stringify({ routes: myRoutes, memberId: d.id, username: d.username });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (sharedKey) {
        res.end(JSON.stringify({ enc: encryptMQTT(payload, sharedKey) }));
      } else {
        res.end(payload);
      }
      return;
    }

    if (p === '/message') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const envelope = JSON.parse(body);
          const d        = readDB();
          const friend   = (d.friends || []).find(f => f.id === envelope.fromId);
          if (!friend) { res.writeHead(403); res.end('No autorizado'); return; }
          const sharedKey = getSharedKey(envelope.fromId);
          if (!sharedKey) { res.writeHead(403); res.end('Sin clave'); return; }
          if (!verifySignature(envelope.payload, envelope.ts, envelope.nonce, envelope.sig, sharedKey)) {
            secLog('INVALID_SIG_MESSAGE', `fromId=${envelope.fromId} ip=${req.socket?.remoteAddress}`);
            res.writeHead(403); res.end('Firma inválida'); return;
          }
          const msg = JSON.parse(envelope.payload);
          if (msg.type === 'tunnel_update') {
            friend.tunnelUrl = msg.tunnelUrl;
            writeDB(d);
            friendStatus[friend.id] = { online: true, lastSeen: Date.now() };
            notifyFriendStatusChange();
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('friends:tunnelUpdated', { friendId: friend.id });
          } else if (msg.type === 'going_offline') {
            friendStatus[friend.id] = { online: false, lastSeen: Date.now() };
            notifyFriendStatusChange();
          } else if (msg.type === 'family_invite') {
            handleFamilyInvite(msg, friend, d);
          } else if (msg.type === 'family_invite_response') {
            handleFamilyInviteResponse(msg, friend, d);
          } else if (msg.type === 'family_removed') {
            handleFamilyRemoved(msg, friend, d);
          } else if (msg.type === 'family_updated') {
            handleFamilyUpdated(msg, friend, d);
          }
          const ts          = Date.now().toString();
          const nonce       = generateNonce();
          const respPayload = JSON.stringify({ tunnelUrl });
          const respSig     = signPayload(respPayload, ts, nonce, sharedKey);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, payload: respPayload, ts, nonce, sig: respSig }));
        } catch (e) {
          secLog('MESSAGE_PARSE_ERROR', `fromId=${envelope?.fromId || 'unknown'} err=${e.message}`);
          res.writeHead(400); res.end('Bad request');
        }
      });
      return;
    }

    res.writeHead(404); res.end('Not found');
  });

  p2pServer.listen(0, '0.0.0.0', () => {
    p2pPort = p2pServer.address().port;
    mapPortUPnP(p2pPort); // Intentar abrir puerto en el router
    startTunnel(p2pPort).then(url => {
      if (!url) { setTunnelStatus('down'); return; }
      tunnelUrl = url;
      setTunnelStatus('online'); // esto ya envía tunnel:status al renderer
      startHeartbeat();
      startFriendMonitor();
      publishTunnelUrl(url);
      syncTunnelToFriends(url).then(() => startRetrySync());
    });
  });
}

// ── App lifecycle ─────────────────────────────────────────────────────────────
function cleanupExpiredInvites() {
  const db = readDB();
  if (!db) return;
  const now = Date.now();
  let dirty = false;
  if (db.pendingFamilyInvites) {
    const before = db.pendingFamilyInvites.length;
    db.pendingFamilyInvites = db.pendingFamilyInvites.filter(i => i.expiresAt > now);
    if (db.pendingFamilyInvites.length !== before) dirty = true;
  }
  if (db.pendingFriendRequests) {
    const before = db.pendingFriendRequests.length;
    db.pendingFriendRequests = db.pendingFriendRequests.filter(r => r.expiresAt > now);
    if (db.pendingFriendRequests.length !== before) dirty = true;
  }
  if (db.sentFriendRequests) {
    const before = db.sentFriendRequests.length;
    db.sentFriendRequests = db.sentFriendRequests.filter(r => r.expiresAt > now);
    if (db.sentFriendRequests.length !== before) dirty = true;
  }
  for (const fam of (db.families || [])) {
    if (fam.pendingInvites) {
      const before = fam.pendingInvites.length;
      fam.pendingInvites = fam.pendingInvites.filter(i => i.expiresAt > now);
      if (fam.pendingInvites.length !== before) dirty = true;
    }
  }
  if (dirty) writeDB(db);
}

// ── Rotación de logs — rotar si superan LOG_MAX_SIZE_BYTES ────────────────────
function rotateLogs() {
  for (const logFile of [ACCESS_LOG_FILE, SEC_LOG_FILE]) {
    try {
      if (!fs.existsSync(logFile)) continue;
      const stat = fs.statSync(logFile);
      if (stat.size > LOG_MAX_SIZE_BYTES) {
        const date = new Date().toISOString().slice(0, 7);
        const ext  = path.extname(logFile);
        const base = logFile.slice(0, -ext.length);
        const dest = `${base}-${date}${ext}`;
        // Si ya existe el archivo rotado de este mes, agregar timestamp completo
        const finalDest = fs.existsSync(dest) ? `${base}-${new Date().toISOString().replace(/[:.]/g,'-')}${ext}` : dest;
        fs.renameSync(logFile, finalDest);
      }
    } catch {}
  }
}

app.whenReady().then(() => {
  createWindow();
  createTray();
  rotateLogs();             // rotación de logs al inicio
  cleanupExpiredInvites();  // limpieza al inicio
  startP2PServer();
  startMQTT();
});
app.on('window-all-closed', e => e.preventDefault());
app.on('before-quit', async e => {
  e.preventDefault();
  stopHeartbeat();
  await notifyFriendsBeforeQuit();
  stopMQTT();
  killTunnel();
  app.exit(0);
});

// ── IPC: Config de recursos ───────────────────────────────────────────────────
ipcMain.handle('settings:getResourceConfig', () => {
  return getResourceConfig();
});

ipcMain.handle('settings:setResourceConfig', (_, config) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  // Validar rangos
  const validated = {};
  const ranges = {
    maxActiveDownloads: [1, 100],
    maxZipWorkers:      [1, 16],
    maxZipSizeGB:       [1, 1000],
    maxBrowseItems:     [0, 10000],
    maxBandwidthMBps:   [0, 10000], // 0 = sin límite
    rateLimitPerMinute: [0, 1000],  // 0 = sin límite
    rateLimitPerFriend: [0, 1000],  // 0 = sin límite
    rateLimitPerRoute:  [0, 1000],  // 0 = sin límite
  };
  for (const [key, [min, max]] of Object.entries(ranges)) {
    if (config[key] !== undefined) {
      const val = Math.round(Number(config[key]));
      // Si min es 0, permitimos 0 como valor especial
      if (isNaN(val) || val < min || val > max) {
        return { error: `${key} debe estar entre ${min} y ${max}` };
      }
      validated[key] = val;
    }
  }

  db.resourceConfig = { ...(db.resourceConfig || {}), ...validated };
  writeDB(db);
  return { success: true, config: getResourceConfig() };
});

// ── IPC: Auth ─────────────────────────────────────────────────────────────────
ipcMain.handle('auth:check', () => {
  const db = readDB();
  return db ? { loggedIn: true, user: { username: db.username, id: db.id, pubKey: db.ecdhPublic } } : { loggedIn: false };
});

ipcMain.handle('auth:register', (_, { username, password }) => {
  if (readDB()) return { error: 'Ya existe una cuenta en este dispositivo' };
  if (!username || username.length < 3) return { error: 'El nombre debe tener al menos 3 caracteres' };
  if (!password || password.length < 4) return { error: 'La contraseña debe tener al menos 4 caracteres' };
  let db = { username: username.trim(), password, id: uuidv4(), friends: [], routes: [], sharedKeys: {}, createdAt: Date.now() };
  db = ensureECDHKeys(db);
  writeDB(db);
  startP2PServer();
  startMQTT();
  return { success: true, user: { username: db.username, id: db.id, pubKey: db.ecdhPublic } };
});

ipcMain.handle('auth:login', (_, { username, password }) => {
  let db = readDB();
  if (!db) return { error: 'No hay cuenta en este dispositivo' };
  if (db.username !== username) return { error: 'Usuario incorrecto' };
  if (db.password !== password) return { error: 'Contraseña incorrecta' };
  db = ensureECDHKeys(db);
  return { success: true, user: { username: db.username, id: db.id, pubKey: db.ecdhPublic } };
});

ipcMain.handle('activity:getHistory', async () => {
  const history = [];
  try {
    if (fs.existsSync(ACCESS_LOG_FILE)) {
      const lines = fs.readFileSync(ACCESS_LOG_FILE, 'utf8').trim().split('\n').slice(-50);
      for (const line of lines) {
        if (!line) continue;
        const match = line.match(/^(\S+) \[([^\]]+)\] friend=([^\s]+) (.*)$/);
        if (match) history.push({ type: 'access', ts: match[1], action: match[2], display: match[3], detail: match[4], raw: line });
      }
    }
    if (fs.existsSync(SEC_LOG_FILE)) {
      const lines = fs.readFileSync(SEC_LOG_FILE, 'utf8').trim().split('\n').slice(-50);
      for (const line of lines) {
        if (!line) continue;
        const match = line.match(/^(\S+) \[([^\]]+)\] (.*)$/);
        if (match) history.push({ type: 'sec', ts: match[1], event: match[2], detail: match[3], raw: line });
      }
    }
  } catch {}
  return history.sort((a, b) => new Date(b.ts) - new Date(a.ts)).slice(0, 50);
});

// ── IPC: Rutas ────────────────────────────────────────────────────────────────
ipcMain.handle('routes:get', () => { const db = readDB(); return db ? db.routes : []; });

ipcMain.handle('routes:add', (_, { name, path: routePath, allowedFriends, familyIds }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  if (!fs.existsSync(routePath)) return { error: 'La ruta no existe' };
  const route = {
    id: uuidv4(),
    name,
    path: routePath,
    allowedFriends: allowedFriends || [],
    familyIds: familyIds || [],
    sync: false, // Por defecto desactivado
    createdAt: Date.now()
  };
  db.routes.push(route);
  writeDB(db);
  return { success: true, route };
});

ipcMain.handle('routes:edit', (_, { id, name, path: routePath, allowedFriends, familyIds }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const route = db.routes.find(r => r.id === id);
  if (!route) return { error: 'Ruta no encontrada' };
  if (name) route.name = name;
  if (routePath !== undefined) {
    if (!fs.existsSync(routePath)) return { error: 'La ruta no existe' };
    route.path = routePath;
  }
  if (allowedFriends !== undefined) route.allowedFriends = allowedFriends;
  if (familyIds !== undefined) route.familyIds = familyIds;
  if (arguments[1].sync !== undefined) route.sync = !!arguments[1].sync;
  writeDB(db);
  return { success: true, route };
});

ipcMain.handle('routes:delete', (_, { id }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  db.routes = db.routes.filter(r => r.id !== id);
  writeDB(db);
  return { success: true };
});

ipcMain.handle('routes:browse', (_, { routeId, subPath }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const route = db.routes.find(r => r.id === routeId);
  if (!route) return { error: 'Ruta no encontrada' };
  const target = subPath ? path.join(route.path, subPath) : route.path;
  if (!target.startsWith(route.path)) return { error: 'Acceso denegado' };
  if (!fs.existsSync(target)) return { error: 'Carpeta no encontrada' };
  try {
    const entries = fs.readdirSync(target, { withFileTypes: true });
    const items   = entries.map(e => {
      const fullPath = path.join(target, e.name); const isDir = e.isDirectory(); let size = null;
      if (!isDir) { try { size = fs.statSync(fullPath).size; } catch {} }
      return { name: e.name, type: isDir?'dir':'file', ext: isDir?'':path.extname(e.name).toLowerCase().slice(1), size, sizeStr: isDir?null:formatBytes(size), fullPath };
    });
    items.sort((a,b) => a.type!==b.type?(a.type==='dir'?-1:1):a.name.localeCompare(b.name,'es',{sensitivity:'base'}));
    return { items, currentPath: subPath || '/' };
  } catch (e) { return { error: e.message }; }
});

ipcMain.handle('routes:folderSize', (_, { routeId, subPath }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const route = db.routes.find(r => r.id === routeId);
  if (!route) return { error: 'Ruta no encontrada' };
  const target = subPath ? path.join(route.path, subPath) : route.path;
  if (!target.startsWith(route.path)) return { error: 'Acceso denegado' };
  return { bytes: getDirSize(target), sizeStr: formatBytes(getDirSize(target)) };
});

ipcMain.handle('routes:downloadZip', async (_, { items }) => {
  // Validar tamaño total antes de generar ZIP
  const cfg = getResourceConfig();
  const maxBytes = cfg.maxZipSizeGB * 1024 * 1024 * 1024;
  let totalBytes = 0;
  for (const item of items) {
    if (item.type === 'dir' && item.basePath) {
      totalBytes += getDirSize(item.basePath);
    } else if (item.type === 'file' && item.fullPath) {
      try { totalBytes += fs.statSync(item.fullPath).size; } catch {}
    }
  }
  if (totalBytes > maxBytes) {
    return { error: `El tamaño total (${formatBytes(totalBytes)}) supera el límite configurado de ${cfg.maxZipSizeGB} GB. Podés aumentar el límite en Ajustes → Control de recursos.` };
  }
  const savePath = await dialog.showSaveDialog(mainWindow, { defaultPath: 'descarga.zip', filters: [{ name: 'ZIP', extensions: ['zip'] }] });
  if (savePath.canceled) return { cancelled: true };
  return runZipWorker(items, savePath.filePath);
});

ipcMain.handle('routes:openFile', async (_, { fullPath }) => {
  const savePath = await dialog.showSaveDialog(mainWindow, { defaultPath: path.basename(fullPath) });
  if (savePath.canceled) return { cancelled: true };
  fs.copyFileSync(fullPath, savePath.filePath);
  return { success: true };
});

ipcMain.handle('routes:getEffectiveAccess', (_, { routeId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const route = db.routes.find(r => r.id === routeId);
  if (!route) return { error: 'Ruta no encontrada' };

  const effectiveFriendIds = new Set(route.allowedFriends || []);
  if (route.families) {
    for (const famId of route.families) {
      const fam = db.families?.find(f => f.id === famId);
      if (fam && fam.members) {
        for (const m of fam.members) effectiveFriendIds.add(m.id);
      }
    }
  }

  const result = [];
  for (const id of effectiveFriendIds) {
    if (id === db.id) continue;
    const friend = db.friends.find(f => f.id === id);
    if (friend) {
      result.push({
        id: friend.id,
        username: friend.username,
        pubKey: friend.pubKey,
        tunnelUrl: friend.tunnelUrl
      });
    }
  }
  return { effectiveFriends: result };
});

// ── IPC: Amigos ───────────────────────────────────────────────────────────────
ipcMain.handle('friends:get', () => { const db = readDB(); return db ? db.friends : []; });

ipcMain.handle('friends:add', async (_, { friendId, friendUsername, tunnelUrl: friendTunnelUrl, friendPubKey }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  if (db.id === friendId) return { error: 'No podés agregarte a vos mismo' };
  if (db.friends.find(f => f.id === friendId)) return { error: 'Ya es tu amigo' };

  // Derivar clave ECDH compartida — una sola vez, se guarda en DB
  if (friendPubKey && db.ecdhPrivate) {
    try {
      if (!db.sharedKeys) db.sharedKeys = {};
      db.sharedKeys[friendId] = deriveSharedKey(db.ecdhPrivate, friendPubKey);
    } catch (e) { console.error('[ECDH] Error:', e.message); }
  }

  db.friends.push({ id: friendId, username: friendUsername, tunnelUrl: friendTunnelUrl || null, pubKey: friendPubKey || null, addedAt: Date.now() });
  writeDB(db);

  // Publicar nuestra URL al nuevo amigo via MQTT cifrado
  if (tunnelUrl && mqttClient?.connected) {
    const sharedKey = getSharedKey(friendId);
    if (sharedKey) {
      try {
        const enc = encryptMQTT(JSON.stringify({ type: 'tunnel_update', tunnelUrl }), sharedKey);
        secLog('METADATA_ENCRYPTED', `friendId=${friendId} route=tunnel_update`);
        mqttClient.publish(`${MQTT_PREFIX}/${friendId}`, JSON.stringify({ fromId: db.id, enc }), { qos: 1 });
      } catch {}
    }
  }

  // Contacto directo inmediato si tiene URL
  if (friendTunnelUrl && tunnelUrl) {
    const sharedKey = getSharedKey(friendId);
    if (sharedKey) {
      try {
        const ts = Date.now().toString();
        const nonce = generateNonce();
        const payload = JSON.stringify({ type: 'tunnel_update', fromId: db.id, tunnelUrl });
        const sig = signPayload(payload, ts, nonce, sharedKey);
        const resp = JSON.parse(await httpPostJSON(`${normalizeAddress(friendTunnelUrl)}/message`, { payload, ts, nonce, sig, fromId: db.id }));
        friendStatus[friendId] = { online: true, lastSeen: Date.now() };
        if (resp.payload) {
          try {
            const rd = JSON.parse(resp.payload);
            if (rd.tunnelUrl) { const d2 = readDB(); const f2 = d2.friends.find(f=>f.id===friendId); if (f2) { f2.tunnelUrl = rd.tunnelUrl; writeDB(d2); } }
          } catch {}
        }
      } catch { friendStatus[friendId] = { online: false, lastSeen: null }; }
      notifyFriendStatusChange();
    }
  }
  return { success: true };
});

ipcMain.handle('friends:remove', (_, { friendId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  db.friends = db.friends.filter(f => f.id !== friendId);
  if (db.sharedKeys) delete db.sharedKeys[friendId];
  // Quitar de todas las familias
  for (const family of (db.families || [])) {
    family.memberIds = family.memberIds.filter(id => id !== friendId);
  }
  writeDB(db);
  return { success: true };
});

ipcMain.handle('friends:updateUrl', async (_, { friendId, tunnelUrl: friendTunnelUrl }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const friend = db.friends.find(f => f.id === friendId);
  if (!friend) return { error: 'Amigo no encontrado' };
  friend.tunnelUrl = friendTunnelUrl;
  writeDB(db);
  if (friendTunnelUrl && tunnelUrl) {
    const sharedKey = getSharedKey(friendId);
    if (sharedKey) {
      try {
        const ts = Date.now().toString(); const nonce = generateNonce();
        const payload = JSON.stringify({ type: 'tunnel_update', fromId: db.id, tunnelUrl });
        const sig = signPayload(payload, ts, nonce, sharedKey);
        await httpPostJSON(`${normalizeAddress(friendTunnelUrl)}/message`, { payload, ts, nonce, sig, fromId: db.id });
        friendStatus[friendId] = { online: true, lastSeen: Date.now() };
      } catch { friendStatus[friendId] = { online: false, lastSeen: null }; }
      notifyFriendStatusChange(); startRetrySync();
    }
  }
  return { success: true };
});

ipcMain.handle('friends:getStatus', () => friendStatus);

// Alias — nombre personalizado visible solo localmente, no afecta la identidad del amigo
ipcMain.handle('friends:setAlias', (_, { friendId, alias }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const friend = db.friends.find(f => f.id === friendId);
  if (!friend) return { error: 'Amigo no encontrado' };
  friend.alias = alias && alias.trim() ? alias.trim() : null;
  writeDB(db);
  return { success: true };
});

ipcMain.handle('p2p:search', async (event, { query }) => {
  const db = readDB();
  if (!query || query.length < 3) return { error: 'Consulta demasiado corta' };
  const requestId = generateNonce();
  let count = 0;
  for (const f of (db.friends || [])) {
    // Solo enviar a amigos que parecen estar online (tienen tunnelUrl reciente)
    // O simplemente a todos y que MQTT gestione la entrega si vuelven
    publishFamilyEvent(f.id, 'search_request', { query, requestId });
    count++;
  }
  return { requestId, friendsCount: count };
});

ipcMain.handle('p2p:getSignedUrl', async (event, { friendId, routeId, path }) => {
  const db = readDB();
  const friend = (db.friends || []).find(f => f.id === friendId);
  if (!friend || !friend.tunnelUrl) return { error: 'Amigo no encontrado o sin URL' };
  const sharedKey = getSharedKey(friendId);
  if (!sharedKey) return { error: 'No hay clave compartida con este amigo' };
  
  const ts    = Date.now().toString();
  const nonce = generateNonce();
  const sig   = signPayload(friendId, ts, nonce, sharedKey);
  
  const url = new URL(`${friend.tunnelUrl}/download`);
  url.searchParams.set('routeId', routeId);
  url.searchParams.set('path', path);
  url.searchParams.set('friendId', db.id);
  url.searchParams.set('ts', ts);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('sig', sig);
  
  return { url: url.toString() };
});

ipcMain.handle('friends:verify', (_, { friendId, verified }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const friend = db.friends.find(f => f.id === friendId);
  if (!friend) return { error: 'Amigo no encontrado' };
  friend.verified = !!verified;
  writeDB(db);
  return { success: true, verified: friend.verified };
});

ipcMain.handle('friends:getAliases', () => {
  const db = readDB();
  if (!db) return {};
  return (db.friends || []).reduce((acc, f) => { if (f.alias) acc[f.id] = f.alias; return acc; }, {});
});

// Resolvemos el nombre efectivo de un amigo (alias si tiene, si no username)
// Usado internamente — no como IPC separado.

// ── IPC: Solicitudes de amistad ───────────────────────────────────────────────

// Enviar solicitud de amistad — solo necesitás el ID del otro usuario
ipcMain.handle('friends:sendRequest', (_, { targetId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  if (!targetId || typeof targetId !== 'string') return { error: 'ID inválido' };
  if (targetId === db.id) return { error: 'No podés enviarte una solicitud a vos mismo' };
  if ((db.friends || []).find(f => f.id === targetId)) return { error: 'Ya es tu amigo' };

  // Verificar que no haya una solicitud pendiente o ya enviada recientemente
  const now = Date.now();
  if (db.sentFriendRequests) {
    const existing = db.sentFriendRequests.find(r => r.toId === targetId && r.expiresAt > now);
    if (existing) return { error: 'Ya le enviaste una solicitud a este usuario. Esperá a que la acepte.' };
  }

  if (!db.sentFriendRequests) db.sentFriendRequests = [];
  db.sentFriendRequests.push({ toId: targetId, sentAt: now, expiresAt: now + FRIEND_REQUEST_TTL });
  writeDB(db);

  // Publicar solicitud al topic MQTT del destinatario — sin cifrar, es primer contacto
  if (mqttClient?.connected) {
    try {
      mqttClient.publish(
        `${MQTT_PREFIX}/${targetId}`,
        JSON.stringify({
          type:         'friend_request',
          fromId:       db.id,
          fromUsername: db.username,
          fromPubKey:   db.ecdhPublic,
        }),
        { qos: 1 }
      );
    } catch (e) {
      secLog('FRIEND_REQUEST_SEND_ERROR', `toId=${targetId} err=${e.message}`);
      return { error: 'Error al enviar la solicitud. Verificá tu conexión.' };
    }
  } else {
    // Sin MQTT — guardar igual, se reintentará cuando reconecte
    secLog('FRIEND_REQUEST_QUEUED_OFFLINE', `toId=${targetId}`);
  }

  secLog('FRIEND_REQUEST_SENT', `toId=${targetId}`);
  return { success: true };
});

// Obtener solicitudes recibidas pendientes
ipcMain.handle('friends:getPendingRequests', () => {
  const db = readDB();
  if (!db) return [];
  const now = Date.now();
  return (db.pendingFriendRequests || []).filter(r => r.expiresAt > now);
});

// Aceptar solicitud de amistad
ipcMain.handle('friends:acceptRequest', (_, { fromId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };

  const request = (db.pendingFriendRequests || []).find(r => r.fromId === fromId);
  if (!request) return { error: 'Solicitud no encontrada o expirada' };
  if (request.expiresAt < Date.now()) {
    db.pendingFriendRequests = db.pendingFriendRequests.filter(r => r.fromId !== fromId);
    writeDB(db);
    return { error: 'La solicitud expiró' };
  }

  // Derivar sharedKey con la pubKey del solicitante
  const myPrivate = db.ecdhPrivate || loadPrivateKey();
  if (!myPrivate) return { error: 'No se pudo acceder a la clave privada' };

  try {
    const sharedKey = deriveSharedKey(myPrivate, request.fromPubKey);
    if (!db.sharedKeys) db.sharedKeys = {};
    db.sharedKeys[fromId] = sharedKey;

    // Agregar como amigo
    if (!db.friends) db.friends = [];
    if (!db.friends.find(f => f.id === fromId)) {
      db.friends.push({
        id:        fromId,
        username:  request.fromUsername,
        pubKey:    request.fromPubKey,
        tunnelUrl: null, // se recibirá via MQTT cuando el otro publique su URL
        addedAt:   Date.now(),
      });
    }

    // Limpiar la solicitud pendiente
    db.pendingFriendRequests = db.pendingFriendRequests.filter(r => r.fromId !== fromId);
    writeDB(db);

    // Notificar al solicitante — mensaje cifrado con la sharedKey recién derivada
    if (mqttClient?.connected) {
      try {
        const enc = encryptMQTT(
          JSON.stringify({ type: 'friend_request_accepted', fromId: db.id, fromUsername: db.username, tunnelUrl: tunnelUrl || null }),
          sharedKey
        );
        mqttClient.publish(
          `${MQTT_PREFIX}/${fromId}`,
          JSON.stringify({ type: 'friend_request_accepted', fromId: db.id, fromPubKey: db.ecdhPublic, enc }),
          { qos: 1 }
        );
      } catch (e) {
        secLog('FRIEND_REQUEST_ACCEPT_NOTIFY_ERROR', `toId=${fromId} err=${e.message}`);
      }
    }

    // Publicar nuestra tunnelUrl al nuevo amigo via MQTT
    if (tunnelUrl && mqttClient?.connected) {
      try {
        const enc = encryptMQTT(JSON.stringify({ type: 'tunnel_update', tunnelUrl }), sharedKey);
        mqttClient.publish(`${MQTT_PREFIX}/${fromId}`, JSON.stringify({ fromId: db.id, enc }), { qos: 1 });
      } catch {}
    }

    friendStatus[fromId] = { online: false, lastSeen: null };
    notifyFriendStatusChange();
    secLog('FRIEND_REQUEST_ACCEPTED_LOCAL', `fromId=${fromId}`);
    return { success: true, friend: { id: fromId, username: request.fromUsername } };
  } catch (e) {
    secLog('FRIEND_REQUEST_ACCEPT_ERROR', `fromId=${fromId} err=${e.message}`);
    return { error: 'Error al procesar la solicitud: ' + e.message };
  }
});

// Rechazar solicitud de amistad
ipcMain.handle('friends:rejectRequest', (_, { fromId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  db.pendingFriendRequests = (db.pendingFriendRequests || []).filter(r => r.fromId !== fromId);
  writeDB(db);
  secLog('FRIEND_REQUEST_REJECTED', `fromId=${fromId}`);
  return { success: true };
});

// ── IPC: Familias ─────────────────────────────────────────────────────────────
//
// Schema en DB:
//   families: [{
//     id, name, createdAt,
//     role: 'owner'|'member',    ← perspectiva local
//     ownerId,                   ← id del creador
//     memberIds: [friendId,...],
//     version: 0,                ← incrementa en cada cambio para detectar estado viejo
//     pendingInvites: [{ toId, sentAt, expiresAt }]   ← solo en el owner
//   }]
//   pendingFamilyInvites: [{     ← invitaciones recibidas aún sin responder
//     familyId, familyName, fromId, fromUsername, receivedAt, expiresAt
//   }]

ipcMain.handle('families:get', () => {
  const db = readDB();
  if (!db) return { owned: [], member: [], pending: [] };
  const now = Date.now();

  // Limpiar invitaciones recibidas expiradas
  if (db.pendingFamilyInvites) {
    db.pendingFamilyInvites = db.pendingFamilyInvites.filter(i => i.expiresAt > now);
  }

  // Limpiar pendingInvites enviadas expiradas (en familias propias)
  let dirty = false;
  for (const fam of (db.families || [])) {
    if (fam.pendingInvites) {
      const before = fam.pendingInvites.length;
      fam.pendingInvites = fam.pendingInvites.filter(i => i.expiresAt > now);
      if (fam.pendingInvites.length !== before) dirty = true;
    }
  }
  if (dirty || db.pendingFamilyInvites) writeDB(db);

  // Adjuntar rutas compartidas por MÍ (el usuario local) para cada familia
  const enrichFamily = (fam) => {
    // Mis propias rutas que publiqué en esta familia
    const mySharedRoutes = (db.routes || [])
      .filter(r => (r.familyIds || []).includes(fam.id))
      .map(r => ({ id: r.id, name: r.name, path: r.path, ownerId: db.id }));
    return { ...fam, mySharedRoutes };
  };

  return {
    owned:   (db.families || []).filter(f => f.ownerId === db.id).map(enrichFamily),
    member:  (db.families || []).filter(f => f.ownerId !== db.id),
    pending: db.pendingFamilyInvites || [],
  };
});

ipcMain.handle('families:create', (_, { name }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  if (!name || !name.trim()) return { error: 'El nombre no puede estar vacío' };
  if (!db.families) db.families = [];
  const family = {
    id: uuidv4(),
    name: name.trim(),
    ownerId: db.id,
    role: 'owner',
    memberIds: [],
    version: 0,
    pendingInvites: [],
    createdAt: Date.now(),
  };
  db.families.push(family);
  writeDB(db);
  return { success: true, family };
});

ipcMain.handle('families:rename', (_, { familyId, name }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const family = (db.families || []).find(f => f.id === familyId && (f.ownerId === db.id || (f.adminIds || []).includes(db.id)));
  if (!family) return { error: 'Familia no encontrada o sin permiso' };
  if (!name || !name.trim()) return { error: 'El nombre no puede estar vacío' };
  family.name = name.trim();
  family.version = (family.version || 0) + 1;
  writeDB(db);
  // Notificar a todos los miembros
  for (const memberId of (family.memberIds || [])) {
    publishFamilyEvent(memberId, 'family_updated', { familyId: family.id, version: family.version });
  }
  return { success: true, family };
});

ipcMain.handle('families:delete', (_, { familyId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const family = (db.families || []).find(f => f.id === familyId && f.ownerId === db.id);
  if (!family) return { error: 'Familia no encontrada o sin permiso' };
  // Notificar expulsión a todos los miembros antes de borrar
  for (const memberId of (family.memberIds || [])) {
    publishFamilyEvent(memberId, 'family_removed', { familyId, fromId: db.id });
  }
  db.families = (db.families || []).filter(f => f.id !== familyId);
  for (const route of (db.routes || [])) {
    if (route.familyIds) route.familyIds = route.familyIds.filter(fid => fid !== familyId);
  }
  writeDB(db);
  return { success: true };
});

ipcMain.handle('families:invite', (_, { familyId, friendId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const family = (db.families || []).find(f => f.id === familyId && (f.ownerId === db.id || (f.adminIds || []).includes(db.id)));
  if (!family) return { error: 'Familia no encontrada o sin permiso' };
  const friend = (db.friends || []).find(f => f.id === friendId);
  if (!friend) return { error: 'Amigo no encontrado' };
  if ((family.memberIds || []).includes(friendId)) return { error: 'Ya es miembro' };
  const expiresAt = Date.now() + FAMILY_INVITE_TTL;
  if (!family.pendingInvites) family.pendingInvites = [];
  // Evitar duplicados
  family.pendingInvites = family.pendingInvites.filter(i => i.toId !== friendId);
  family.pendingInvites.push({ toId: friendId, sentAt: Date.now(), expiresAt });
  writeDB(db);
  publishFamilyEvent(friendId, 'family_invite', { familyId: family.id, familyName: family.name, expiresAt });
  return { success: true };
});

ipcMain.handle('families:acceptInvite', async (_, { familyId, fromId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const invite = (db.pendingFamilyInvites || []).find(i => i.familyId === familyId && i.fromId === fromId);
  if (!invite) return { error: 'Invitación no encontrada o expirada' };
  if (invite.expiresAt < Date.now()) {
    db.pendingFamilyInvites = db.pendingFamilyInvites.filter(i => !(i.familyId === familyId && i.fromId === fromId));
    writeDB(db);
    return { error: 'La invitación expiró' };
  }
  // Pull del estado real de la familia desde el owner
  const owner = (db.friends || []).find(f => f.id === fromId);
  let familyState = null;
  if (owner?.tunnelUrl) {
    try {
      const sharedKey = getSharedKey(fromId);
      if (sharedKey) {
        const base  = normalizeAddress(owner.tunnelUrl);
        const ts    = Date.now().toString();
        const nonce = generateNonce();
        const sig   = signPayload(`/family-sync:${db.id}`, ts, nonce, sharedKey);
        const raw   = await httpGetAny(`${base}/family-sync?familyId=${encodeURIComponent(familyId)}&friendId=${encodeURIComponent(db.id)}&ts=${ts}&nonce=${nonce}&sig=${sig}`);
        familyState = JSON.parse(raw);
      }
    } catch (e) { console.error('[FAMILY ACCEPT SYNC]', e.message); }
  }
  // Agregar familia a DB local
  if (!db.families) db.families = [];
  const existing = db.families.find(f => f.id === familyId);
  if (!existing) {
    db.families.push({
      id: familyId,
      name: familyState?.name || invite.familyName,
      ownerId: fromId,
      role: 'member',
      memberIds: familyState?.memberIds || [],
      version: familyState?.version || 0,
      createdAt: Date.now(),
    });
  }
  // Quitar invitación pendiente
  db.pendingFamilyInvites = (db.pendingFamilyInvites || []).filter(i => !(i.familyId === familyId && i.fromId === fromId));
  writeDB(db);
  // Notificar al owner
  publishFamilyEvent(fromId, 'family_invite_response', { familyId, accepted: true });
  return { success: true };
});

ipcMain.handle('families:rejectInvite', (_, { familyId, fromId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  db.pendingFamilyInvites = (db.pendingFamilyInvites || []).filter(i => !(i.familyId === familyId && i.fromId === fromId));
  writeDB(db);
  publishFamilyEvent(fromId, 'family_invite_response', { familyId, accepted: false });
  return { success: true };
});

ipcMain.handle('families:leave', (_, { familyId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const idx = (db.families || []).findIndex(f => f.id === familyId && f.role === 'member');
  if (idx === -1) return { error: 'Familia no encontrada' };
  const family = db.families[idx];
  // Notificar al owner antes de borrar
  publishFamilyEvent(family.ownerId, 'family_removed', { familyId, fromId: db.id });
  db.families.splice(idx, 1);
  writeDB(db);
  return { success: true };
});

ipcMain.handle('families:addMember', (_, { familyId, friendId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const family = (db.families || []).find(f => f.id === familyId && f.ownerId === db.id);
  if (!family) return { error: 'Familia no encontrada o sin permiso' };
  if (!db.friends.find(f => f.id === friendId)) return { error: 'Amigo no encontrado' };
  if ((family.memberIds || []).includes(friendId)) return { error: 'Ya es miembro' };
  family.memberIds.push(friendId);
  family.version = (family.version || 0) + 1;
  writeDB(db);
  // Notificar al resto de miembros del cambio
  for (const memberId of family.memberIds) {
    if (memberId !== friendId) publishFamilyEvent(memberId, 'family_updated', { familyId: family.id, version: family.version });
  }
  return { success: true, family };
});

ipcMain.handle('families:removeMember', (_, { familyId, friendId }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const family = (db.families || []).find(f => f.id === familyId && f.ownerId === db.id);
  if (!family) return { error: 'Familia no encontrada o sin permiso' };
  family.memberIds = (family.memberIds || []).filter(id => id !== friendId);
  family.version = (family.version || 0) + 1;
  writeDB(db);
  // Notificar al expulsado
  publishFamilyEvent(friendId, 'family_removed', { familyId, fromId: db.id });
  // Notificar al resto que el estado cambió
  for (const memberId of family.memberIds) {
    publishFamilyEvent(memberId, 'family_updated', { familyId: family.id, version: family.version });
  }
  return { success: true, family };
});

// Asociar/desasociar una ruta con una familia (solo owner de la familia)
ipcMain.handle('families:setRouteFamily', (_, { routeId, familyId, enabled }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const route = (db.routes || []).find(r => r.id === routeId);
  if (!route) return { error: 'Ruta no encontrada' };
  if (!(db.families || []).find(f => f.id === familyId)) return { error: 'Familia no encontrada' };
  if (!route.familyIds) route.familyIds = [];
  if (enabled) {
    if (!route.familyIds.includes(familyId)) route.familyIds.push(familyId);
  } else {
    route.familyIds = route.familyIds.filter(fid => fid !== familyId);
  }
  writeDB(db);
  // Notificar a miembros que el estado de la familia cambió (versión incrementa)
  const family = db.families.find(f => f.id === familyId);
  if (family && family.ownerId === db.id) {
    family.version = (family.version || 0) + 1;
    writeDB(db);
    for (const memberId of (family.memberIds || [])) {
      publishFamilyEvent(memberId, 'family_updated', { familyId: family.id, version: family.version });
    }
  }
  return { success: true, route };
});

ipcMain.handle('families:promoteMember', (_, { familyId, friendId }) => {
  const db = readDB();
  const f = (db.families || []).find(f => f.id === familyId && f.ownerId === db.id);
  if (!f) return { error: 'No autorizado' };
  if (!f.adminIds) f.adminIds = [];
  if (!f.adminIds.includes(friendId)) f.adminIds.push(friendId);
  f.version = (f.version || 0) + 1;
  writeDB(db);
  f.memberIds.forEach(id => { if (id !== db.id) publishFamilyEvent(id, 'family_updated', { familyId: f.id, version: f.version }); });
  return { success: true };
});

ipcMain.handle('families:demoteMember', (_, { familyId, friendId }) => {
  const db = readDB();
  const f = (db.families || []).find(f => f.id === familyId && f.ownerId === db.id);
  if (!f) return { error: 'No autorizado' };
  if (!f.adminIds) f.adminIds = [];
  f.adminIds = f.adminIds.filter(id => id !== friendId);
  f.version = (f.version || 0) + 1;
  writeDB(db);
  f.memberIds.forEach(id => { if (id !== db.id) publishFamilyEvent(id, 'family_updated', { familyId: f.id, version: f.version }); });
  return { success: true };
});

// ── IPC: P2P ──────────────────────────────────────────────────────────────────
ipcMain.handle('p2p:getMyAddress', () => ({ tunnelUrl, port: p2pPort, localIp: getLocalIp(), tunnelStatus }));

// Devuelve el ID del usuario — lo único que necesita el otro para enviar una solicitud
ipcMain.handle('p2p:getMyAddString', () => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  return { addString: db.id };
});

ipcMain.handle('p2p:getFingerprint', (_, { pubKey }) => {
  if (!pubKey) { const db = readDB(); pubKey = db?.ecdhPublic; }
  return pubKey ? getFingerprint(pubKey) : null;
});

ipcMain.handle('p2p:connect', async (_, { address, myId }) => {
  try {
    const base      = normalizeAddress(address);
    const info      = JSON.parse(await httpGetAny(`${base}/info`));
    const sharedKey = getSharedKey(info.id);
    if (!sharedKey) return { error: 'No tenés clave con este usuario. Agregalo como amigo primero.' };
    const ts    = Date.now().toString();
    const nonce = generateNonce();
    const sig   = signPayload(`/routes:${myId}`, ts, nonce, sharedKey);
    const raw   = await httpGetAny(`${base}/routes?friendId=${myId}&ts=${ts}&nonce=${nonce}&sig=${sig}`);
    let data    = JSON.parse(raw);
    if (data.enc) data = JSON.parse(decryptMQTT(data.enc, sharedKey));
    return { success: true, host: info, routes: data.routes, address: base };
  } catch (e) { return { error: 'No se pudo conectar: ' + e.message }; }
});

ipcMain.handle('p2p:browse', async (_, { address, routeId, subPath, myId }) => {
  try {
    const base      = normalizeAddress(address);
    const info      = JSON.parse(await httpGetAny(`${base}/info`));
    const sharedKey = getSharedKey(info.id);
    if (!sharedKey) return { error: 'Sin clave compartida' };
    const ts    = Date.now().toString();
    const nonce = generateNonce();
    const sig   = signPayload(`/browse:${myId}`, ts, nonce, sharedKey);
    const sp    = subPath ? `&path=${encodeURIComponent(subPath)}` : '';
    const raw   = await httpGetAny(`${base}/browse?routeId=${routeId}&friendId=${myId}&ts=${ts}&nonce=${nonce}&sig=${sig}${sp}`);
    let data    = JSON.parse(raw);
    if (data.enc) data = JSON.parse(decryptMQTT(data.enc, sharedKey));
    return data;
  } catch (e) { return { error: e.message }; }
});

ipcMain.handle('p2p:downloadFile', async (_, { address, routeId, filePath, myId }) => {
  const savePath = await dialog.showSaveDialog(mainWindow, { defaultPath: path.basename(filePath) });
  if (savePath.canceled) return { cancelled: true };
  
  const downloadId = uuidv4();
  const item = {
    id: downloadId,
    address,
    routeId,
    filePath,
    destPath: savePath.filePath,
    fileName: path.basename(filePath),
    status: 'queued',
    progress: 0,
    addedAt: Date.now()
  };
  
  outgoingQueue.push(item);
  processOutgoingQueue();
  return { success: true, downloadId };
});

function processOutgoingQueue() {
  const max = getResourceConfig().maxActiveDownloads || 3;
  if (activeOutgoingDownloads >= max) return;
  
  const next = outgoingQueue.find(i => i.status === 'queued');
  if (!next) return;
  
  next.status = 'downloading';
  activeOutgoingDownloads++;
  
  runDownload(next).finally(() => {
    activeOutgoingDownloads--;
    processOutgoingQueue();
  });
}

async function runDownload(item) {
  try {
    const base      = normalizeAddress(item.address);
    const info      = JSON.parse(await httpGetAny(`${base}/info`));
    const sharedKey = getSharedKey(info.id);
    if (!sharedKey) throw new Error('Sin clave compartida');
    
    const db = readDB();
    const ts    = Date.now().toString();
    const nonce = generateNonce();
    const sig   = signPayload(`/download:${db.id}`, ts, nonce, sharedKey);
    const url   = `${base}/download?routeId=${encodeURIComponent(item.routeId)}&path=${encodeURIComponent(item.filePath)}&friendId=${encodeURIComponent(db.id)}&ts=${ts}&nonce=${nonce}&sig=${sig}`;
    
    await httpDownloadToFile(url, item.destPath, (downloaded, total) => {
      item.progress = Math.floor((downloaded / total) * 100);
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('download:progress', { id: item.id, progress: item.progress, fileName: item.fileName });
      }
    });
    
    item.status = 'completed';
    secLog('FILE_DOWNLOAD_COMPLETE', `file=${item.fileName} from=${info.username}`);
  } catch (e) {
    item.status = 'error';
    item.error = e.message;
    secLog('FILE_DOWNLOAD_ERROR', `file=${item.fileName} err=${e.message}`);
  }
}

ipcMain.handle('p2p:getDownloadQueue', () => {
  return outgoingQueue.map(i => ({ id: i.id, fileName: i.fileName, status: i.status, progress: i.progress }));
});

ipcMain.handle('families:sendChat', (_, { familyId, text }) => {
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  const family = (db.families || []).find(f => f.id === familyId);
  if (!family) return { error: 'Familia no encontrada' };
  
  const payload = { type: 'family_chat', familyId, text, ts: Date.now() };
  family.memberIds.forEach(id => {
    if (id !== db.id) publishFamilyEvent(id, 'family_chat', payload);
  });
  return { success: true };
});

ipcMain.handle('p2p:folderSize', async (_, { address, routeId, subPath, myId }) => {
  try {
    const base      = normalizeAddress(address);
    const info      = JSON.parse(await httpGetAny(`${base}/info`));
    const sharedKey = getSharedKey(info.id);
    if (!sharedKey) return { error: 'Sin clave compartida' };
    const ts    = Date.now().toString();
    const nonce = generateNonce();
    const sig   = signPayload(`/folder-size:${myId}`, ts, nonce, sharedKey);
    const sp    = subPath ? `&path=${encodeURIComponent(subPath)}` : '';
    const raw   = await httpGetAny(`${base}/folder-size?routeId=${routeId}&friendId=${myId}&ts=${ts}&nonce=${nonce}&sig=${sig}${sp}`);
    let data    = JSON.parse(raw);
    if (data.enc) data = JSON.parse(decryptMQTT(data.enc, sharedKey));
    return data;
  } catch (e) { return { error: e.message }; }
});

ipcMain.handle('p2p:downloadZip', async (_, { items, address, myId }) => {
  const savePath = await dialog.showSaveDialog(mainWindow, { defaultPath: 'descarga.zip', filters: [{ name: 'ZIP', extensions: ['zip'] }] });
  if (savePath.canceled) return { cancelled: true };
  try {
    const base      = normalizeAddress(address);
    const info      = JSON.parse(await httpGetAny(`${base}/info`));
    const sharedKey = getSharedKey(info.id);
    if (!sharedKey) return { error: 'Sin clave compartida' };
    const tmpDir     = path.join(DATA_DIR, 'tmp_zip_' + Date.now());
    fs.mkdirSync(tmpDir, { recursive: true });
    const localItems = [];
    for (const item of items) {
      const ts      = Date.now().toString();
      const nonce   = generateNonce();
      const sig     = signPayload(`/download:${myId}`, ts, nonce, sharedKey);
      const url     = `${base}/download?routeId=${encodeURIComponent(item.routeId)}&path=${encodeURIComponent(item.filePath)}&friendId=${encodeURIComponent(myId)}&ts=${ts}&nonce=${nonce}&sig=${sig}`;
      const tmpFile = path.join(tmpDir, uuidv4());
      await httpDownloadToFile(url, tmpFile);
      localItems.push({ fullPath: tmpFile, zipPath: item.zipPath });
    }
    const result = await runZipWorker(localItems, savePath.filePath);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    return result;
  } catch (e) { return { error: e.message }; }
});

// Obtener las rutas que un miembro publicó en una familia
ipcMain.handle('p2p:getFamilyMemberRoutes', async (_, { address, familyId, myId }) => {
  try {
    const base      = normalizeAddress(address);
    const info      = JSON.parse(await httpGetAny(`${base}/info`));
    const sharedKey = getSharedKey(info.id);
    if (!sharedKey) return { error: 'Sin clave compartida' };
    const ts    = Date.now().toString();
    const nonce = generateNonce();
    const sig   = signPayload(`/family-member-routes:${myId}`, ts, nonce, sharedKey);
    const raw   = await httpGetAny(
      `${base}/family-member-routes?familyId=${encodeURIComponent(familyId)}&friendId=${encodeURIComponent(myId)}&ts=${ts}&nonce=${nonce}&sig=${sig}`
    );
    let data = JSON.parse(raw);
    if (data.enc) data = JSON.parse(decryptMQTT(data.enc, sharedKey));
    return { success: true, ...data };
  } catch (e) { return { error: e.message }; }
});


ipcMain.handle('system:selectFolder',   async () => { const r = await dialog.showOpenDialog(mainWindow, { properties: ['openDirectory'] }); return r.canceled ? null : r.filePaths[0]; });
ipcMain.on('system:minimize', () => mainWindow.minimize());
ipcMain.on('system:maximize', () => { if (mainWindow.isMaximized()) mainWindow.unmaximize(); else mainWindow.maximize(); });
ipcMain.on('system:close',    () => mainWindow.hide());
ipcMain.on('system:openDataFolder', () => { require('electron').shell.openPath(DATA_DIR); });
ipcMain.on('system:checkUpdates',   () => { checkUpdates(true); });
ipcMain.handle('system:getAutostart',   () => getLoginItem());
ipcMain.handle('system:setAutostart',   (_, { enable }) => { setLoginItem(enable); return { success: true, enabled: getLoginItem() }; });
ipcMain.handle('system:getTunnelStatus',() => ({ status: tunnelStatus, url: tunnelUrl }));

// Leer logs de acceso y seguridad para mostrarlos en la UI
ipcMain.handle('system:getAccessLog', () => {
  try {
    if (!fs.existsSync(ACCESS_LOG_FILE)) return { lines: [] };
    const raw   = fs.readFileSync(ACCESS_LOG_FILE, 'utf8');
    const lines = raw.trim().split('\n').filter(Boolean).reverse().slice(0, 200);
    return { lines };
  } catch (e) { return { lines: [], error: e.message }; }
});

ipcMain.handle('system:getSecurityLog', () => {
  try {
    if (!fs.existsSync(SEC_LOG_FILE)) return { lines: [] };
    const raw   = fs.readFileSync(SEC_LOG_FILE, 'utf8');
    const lines = raw.trim().split('\n').filter(Boolean).reverse().slice(0, 200);
    return { lines };
  } catch (e) { return { lines: [], error: e.message }; }
});

// ── IPC: Identidad — Exportar / Importar ──────────────────────────────────────
//
// Formato del archivo .eggid (todo dentro del payload cifrado — nada afuera sin autenticar):
// {
//   version: 1,
//   salt: <hex>,           ← para PBKDF2, está fuera del cifrado (necesario para derivar)
//   iv:   <hex>,           ← IV de AES-256-GCM
//   tag:  <hex>,           ← auth tag GCM
//   data: <hex>            ← payload cifrado = JSON con identidad completa
// }
//
// Payload cifrado contiene:
// { version, id, username, ecdhPublic, ecdhPrivate, friends: [{id,username,pubKey,tunnelUrl}] }
// ❌ NO incluye sharedKeys — se recalculan con ECDH al reconectar
//
// Cifrado: AES-256-GCM, clave derivada con PBKDF2-SHA512, 1.000.000 iteraciones, salt 32 bytes
// Toda la metadata (salt, iv, tag) está cubierta por la autenticación GCM vía AAD

const EGGID_VERSION    = 1;
const PBKDF2_ITER      = 1_000_000;   // 1M iteraciones — resistente a GPU
const PBKDF2_DIGEST    = 'sha512';
const PBKDF2_KEYLEN    = 32;          // 256 bits para AES-256

function deriveKeyFromPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, PBKDF2_ITER, PBKDF2_KEYLEN, PBKDF2_DIGEST, (err, key) => {
      if (err) reject(err); else resolve(key);
    });
  });
}

ipcMain.handle('identity:export', async (_, { password }) => {
  if (!password || password.length < 8) return { error: 'La contraseña debe tener al menos 8 caracteres' };
  const db = readDB();
  if (!db) return { error: 'No hay cuenta activa' };

  const privKey = db.ecdhPrivate || loadPrivateKey();
  if (!privKey) return { error: 'No se pudo acceder a la clave privada' };

  // Elegir destino
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Exportar identidad EggFile',
    defaultPath: `${db.username}_eggfile.eggid`,
    filters: [{ name: 'EggFile Identity', extensions: ['eggid'] }],
  });
  if (result.canceled) return { cancelled: true };

  try {
    // Payload — sin sharedKeys, se recalculan con ECDH al reconectar
    const payload = JSON.stringify({
      version:     EGGID_VERSION,
      id:          db.id,
      username:    db.username,
      ecdhPublic:  db.ecdhPublic,
      ecdhPrivate: privKey,
      friends:     (db.friends || []).map(f => ({
        id:        f.id,
        username:  f.username,
        pubKey:    f.pubKey    || null,
        tunnelUrl: f.tunnelUrl || null,
      })),
    });

    const salt = crypto.randomBytes(32);
    const iv   = crypto.randomBytes(12);
    const key  = await deriveKeyFromPassword(password, salt);

    // AAD = salt + iv — autentica la metadata externa también
    const aad    = Buffer.concat([salt, iv]);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad);
    const enc = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    key.fill(0); // limpiar clave derivada de memoria

    const fileData = JSON.stringify({
      version: EGGID_VERSION,
      salt:    salt.toString('hex'),
      iv:      iv.toString('hex'),
      tag:     tag.toString('hex'),
      data:    enc.toString('hex'),
    });

    fs.writeFileSync(result.filePath, fileData, 'utf8');
    secLog('IDENTITY_EXPORTED', `user=${db.username}`);
    return { success: true };
  } catch (e) {
    secLog('IDENTITY_EXPORT_ERROR', e.message);
    return { error: 'Error al exportar: ' + e.message };
  }
});

ipcMain.handle('identity:import', async (_, { password }) => {
  if (!password || password.length < 8) return { error: 'Contraseña demasiado corta (mínimo 8 caracteres)' };

  // Elegir archivo
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Importar identidad EggFile',
    filters: [{ name: 'EggFile Identity', extensions: ['eggid'] }],
    properties: ['openFile'],
  });
  if (result.canceled) return { cancelled: true };

  try {
    const raw      = fs.readFileSync(result.filePaths[0], 'utf8');
    const file     = JSON.parse(raw);

    if (file.version !== EGGID_VERSION) return { error: `Versión de archivo no soportada (v${file.version})` };
    if (!file.salt || !file.iv || !file.tag || !file.data) return { error: 'Archivo .eggid inválido o corrupto' };

    const salt = Buffer.from(file.salt, 'hex');
    const iv   = Buffer.from(file.iv,   'hex');
    const tag  = Buffer.from(file.tag,  'hex');
    const enc  = Buffer.from(file.data, 'hex');
    const key  = await deriveKeyFromPassword(password, salt);

    // Verificar AAD — detecta si salt o iv fueron manipulados
    const aad     = Buffer.concat([salt, iv]);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    let payload;
    try {
      const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
      payload = JSON.parse(dec.toString('utf8'));
      key.fill(0); // limpiar clave derivada de memoria
    } catch {
      // GCM auth failure → contraseña incorrecta o archivo corrupto
      secLog('IDENTITY_IMPORT_AUTH_FAIL', `file=${result.filePaths[0]}`);
      return { error: 'Contraseña incorrecta o archivo corrupto' };
    }

    if (!payload.id || typeof payload.id !== 'string' ||
        !payload.username || typeof payload.username !== 'string' ||
        !payload.ecdhPublic || typeof payload.ecdhPublic !== 'string' ||
        !payload.ecdhPrivate || typeof payload.ecdhPrivate !== 'string' ||
        !Array.isArray(payload.friends)) {
      return { error: 'Archivo .eggid incompleto o corrupto' };
    }
    for (const f of payload.friends) {
      if (!f.id || typeof f.id !== 'string' ||
          !f.username || typeof f.username !== 'string' ||
          (f.pubKey && typeof f.pubKey !== 'string') ||
          (f.tunnelUrl && typeof f.tunnelUrl !== 'string')) {
        return { error: 'Archivo .eggid contiene datos de amigos inválidos' };
      }
    }

    // Si ya existe una cuenta, bloquear (no sobreescribir silenciosamente)
    if (readDB()) return { error: 'Ya existe una cuenta en este dispositivo. Eliminala primero desde Ajustes.' };

    // Recalcular sharedKeys con ECDH para cada amigo que tenga clave pública
    const sharedKeys = {};
    for (const friend of (payload.friends || [])) {
      if (friend.pubKey) {
        try {
          sharedKeys[friend.id] = deriveSharedKey(payload.ecdhPrivate, friend.pubKey);
        } catch { /* pubKey inválida — se ignorará */ }
      }
    }

    // Guardar clave privada en safeStorage
    const db = {
      username:   payload.username,
      password:   '',            // sin contraseña hasta que el usuario la establezca
      id:         payload.id,
      ecdhPublic: payload.ecdhPublic,
      friends:    payload.friends || [],
      routes:     [],
      sharedKeys,
      createdAt:  Date.now(),
      restoredAt: Date.now(),
    };

    if (!savePrivateKey(payload.ecdhPrivate)) {
      db.ecdhPrivate = payload.ecdhPrivate; // fallback si safeStorage no disponible
    }

    writeDB(db);
    secLog('IDENTITY_IMPORTED', `user=${payload.username} friends=${payload.friends?.length || 0}`);

    return {
      success:     true,
      user:        { username: db.username, id: db.id, pubKey: db.ecdhPublic },
      friendCount: (payload.friends || []).length,
      needsPassword: true,   // señal para que la UI pida establecer nueva contraseña
    };
  } catch (e) {
    secLog('IDENTITY_IMPORT_ERROR', e.message);
    return { error: 'Error al importar: ' + e.message };
  }
});

// Cambiar contraseña post-importación (o en cualquier momento)
ipcMain.handle('identity:setPassword', (_, { newPassword }) => {
  if (!newPassword || newPassword.length < 4) return { error: 'La contraseña debe tener al menos 4 caracteres' };
  const db = readDB();
  if (!db) return { error: 'No autenticado' };
  db.password = newPassword;
  writeDB(db);
  return { success: true };
});

// Eliminar cuenta local (para poder importar otra)
ipcMain.handle('identity:deleteAccount', async () => {
  const confirm = await dialog.showMessageBox(mainWindow, {
    type: 'warning',
    title: 'Eliminar cuenta',
    message: '¿Estás seguro? Esta acción elimina tu cuenta local permanentemente.',
    detail: 'Tus amigos y rutas se borrarán. Exportá tu identidad antes si querés recuperarla.',
    buttons: ['Cancelar', 'Eliminar'],
    defaultId: 0,
    cancelId: 0,
  });
  if (confirm.response !== 1) return { cancelled: true };
  try {
    if (fs.existsSync(DB_FILE))  fs.unlinkSync(DB_FILE);
    const privkeyPath = path.join(DATA_DIR, 'privkey.enc');
    if (fs.existsSync(privkeyPath)) fs.unlinkSync(privkeyPath);
    secLog('ACCOUNT_DELETED', '');
    killTunnel();
    stopMQTT();
    return { success: true };
  } catch (e) { return { error: e.message }; }
});

// ── ZIP Worker Thread ─────────────────────────────────────────────────────────
function runZipWorker(items, destPath) {
  return new Promise((resolve) => {
    if (activeZipWorkers >= getResourceConfig().maxZipWorkers) {
      zipQueue.push({ items, destPath, resolve });
      return;
    }
    _startZipWorker(items, destPath, resolve);
  });
}

function _startZipWorker(items, destPath, resolve) {
  activeZipWorkers++;
  const worker = new Worker(ZIP_WORKER, { workerData: { items, destPath } });
  
  const finish = (result) => {
    activeZipWorkers--;
    resolve(result);
    if (zipQueue.length > 0 && activeZipWorkers < getResourceConfig().maxZipWorkers) {
      const next = zipQueue.shift();
      _startZipWorker(next.items, next.destPath, next.resolve);
    }
  };

  worker.on('message', msg => {
    if (msg.type === 'progress' && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('zip:progress', { current: msg.done, total: msg.total });
    }
    if (msg.type === 'done')  finish({ success: true });
    if (msg.type === 'error') finish({ error: msg.message });
  });
  worker.on('error', err => finish({ error: err.message }));
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function normalizeAddress(address) {
  if (!address) return '';
  address = address.trim().replace(/\/$/, '');
  if (address.startsWith('http://') || address.startsWith('https://')) return address;
  return `http://${address}`;
}

function httpPostJSON(url, data) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(data);
    const mod  = url.startsWith('https') ? https : http;
    const opts = Object.assign(require('url').parse(url), { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }, timeout: 10000 });
    const req  = mod.request(opts, res => { let d=''; res.on('data', c => d+=c); res.on('end', () => resolve(d)); });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(body); req.end();
  });
}

function httpGetAny(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 15000 }, res => { 
      let d=''; 
      res.on('data', c => d+=c); 
      res.on('end', () => {
        if (res.statusCode >= 400) {
          try {
            const parsed = JSON.parse(d);
            reject(new Error(parsed.error || `HTTP ${res.statusCode}`));
          } catch {
            const preview = d.replace(/<[^>]*>?/gm, '').trim().slice(0, 50);
            reject(new Error(`HTTP ${res.statusCode}${preview ? ': ' + preview : ''}`));
          }
        } else {
          resolve(d);
        }
      }); 
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Tiempo de espera agotado (Timeout)')); });
  });
}

function httpDownloadToFile(url, destPath, onProgress) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 60000 }, res => {
      if (res.statusCode >= 400) {
        let d=''; 
        res.on('data', c => d+=c);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(d);
            reject(new Error(parsed.error || `HTTP ${res.statusCode}`));
          } catch {
            const preview = d.replace(/<[^>]*>?/gm, '').trim().slice(0, 50);
            reject(new Error(`HTTP ${res.statusCode}${preview ? ': ' + preview : ''}`));
          }
        });
        return;
      }
      
      const total = parseInt(res.headers['content-length'], 10);
      let downloaded = 0;
      
      const file = fs.createWriteStream(destPath);
      res.on('data', chunk => {
        downloaded += chunk.length;
        if (onProgress && total) onProgress(downloaded, total);
      });
      
      res.pipe(file);
      file.on('finish', () => file.close(resolve));
      file.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Tiempo de espera agotado (Timeout)')); });
  });
}

function formatBytes(bytes) {
  if (bytes == null) return '—';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes/1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes/1048576).toFixed(1) + ' MB';
  return (bytes/1073741824).toFixed(2) + ' GB';
}

function getDirSize(dirPath) {
  let total = 0;
  try { for (const e of fs.readdirSync(dirPath, { withFileTypes: true })) { const full = path.join(dirPath, e.name); try { total += e.isDirectory() ? getDirSize(full) : fs.statSync(full).size; } catch {} } } catch {}
  return total;
}

function getLocalIp() {
  const { networkInterfaces } = require('os');
  for (const iface of Object.values(networkInterfaces())) for (const addr of iface) if (addr.family === 'IPv4' && !addr.internal) return addr.address;
  return '127.0.0.1';
}
