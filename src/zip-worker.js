// zip-worker.js — corre en worker_threads, no bloquea el proceso principal
const { workerData, parentPort } = require('worker_threads');
const fs   = require('fs');
const path = require('path');

// workerData: { items: [{basePath, relPath, type}], destPath }
// items: lista de archivos/carpetas a incluir
// destPath: ruta donde guardar el ZIP

// ZIP sin compresión (stored) — formato ZIP mínimo implementado a mano
// para no depender de librerías externas de compresión

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  const table = crc32.table || (crc32.table = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[i] = c;
    }
    return t;
  })());
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function dosDateTime(date) {
  const d = date || new Date();
  const dosDate = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  const dosTime = (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2);
  return { date: dosDate, time: dosTime };
}

function writeUInt16LE(val) {
  const b = Buffer.alloc(2); b.writeUInt16LE(val); return b;
}
function writeUInt32LE(val) {
  const b = Buffer.alloc(4); b.writeUInt32LE(val >>> 0); return b;
}

function collectFiles(basePath, relPath) {
  const fullPath = relPath ? path.join(basePath, relPath) : basePath;
  const results = [];
  try {
    const entries = fs.readdirSync(fullPath, { withFileTypes: true });
    for (const e of entries) {
      const entryRel  = relPath ? relPath + '/' + e.name : e.name;
      const entryFull = path.resolve(path.join(basePath, entryRel));
      // Path traversal — nunca salir del basePath
      if (!entryFull.startsWith(path.resolve(basePath))) continue;
      if (e.isDirectory()) {
        results.push({ type: 'dir', relPath: entryRel + '/' });
        results.push(...collectFiles(basePath, entryRel));
      } else {
        results.push({ type: 'file', relPath: entryRel, fullPath: entryFull });
      }
    }
  } catch {}
  return results;
}

// Calcula CRC32 de un archivo por streaming para no cargarlo entero en RAM
function crc32File(filePath) {
  return new Promise((resolve, reject) => {
    let crc = 0xFFFFFFFF;
    const table = crc32.table || (crc32.table = (() => {
      const t = new Uint32Array(256);
      for (let i = 0; i < 256; i++) {
        let c = i;
        for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        t[i] = c;
      }
      return t;
    })());
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => {
      for (let i = 0; i < chunk.length; i++) crc = table[(crc ^ chunk[i]) & 0xFF] ^ (crc >>> 8);
    });
    stream.on('end',   () => resolve((crc ^ 0xFFFFFFFF) >>> 0));
    stream.on('error', reject);
  });
}

// Escribe un archivo al stream de salida en chunks — no lo carga entero en RAM
function streamFileTo(filePath, out) {
  return new Promise((resolve, reject) => {
    const rs = fs.createReadStream(filePath);
    rs.on('data', chunk => {
      if (!out.write(chunk)) rs.pause();
    });
    out.on('drain', () => rs.resume());
    rs.on('end',   resolve);
    rs.on('error', reject);
  });
}

async function buildZip() {
  const { items, destPath } = workerData;
  const out = fs.createWriteStream(destPath);
  const centralDir = [];
  let offset = 0;
  let fileCount = 0;

  const write = (buf) => new Promise((res, rej) => {
    if (out.write(buf)) res();
    else out.once('drain', res);
    out.once('error', rej);
  });

  // Expandir items (archivos sueltos + carpetas recursivas)
  const allEntries = [];
  for (const item of items) {
    if (item.type === 'file') {
      allEntries.push({ type: 'file', relPath: path.basename(item.fullPath), fullPath: item.fullPath });
    } else if (item.type === 'dir') {
      // carpeta: usar el nombre de la carpeta como raíz en el ZIP
      const dirName = path.basename(item.basePath);
      allEntries.push({ type: 'dir', relPath: dirName + '/' });
      const sub = collectFiles(item.basePath, '');
      for (const s of sub) {
        allEntries.push({
          type: s.type,
          relPath: dirName + '/' + s.relPath,
          fullPath: s.fullPath,
        });
      }
    }
  }

  for (const entry of allEntries) {
    const nameBytes = Buffer.from(entry.relPath, 'utf8');
    const isDir = entry.type === 'dir';
    let stat = null;
    let size = 0;
    let fileCrc = 0;

    if (!isDir) {
      try {
        stat = fs.statSync(entry.fullPath);
        size = stat.size;
        // Calcular CRC32 por streaming — no carga el archivo entero en RAM
        fileCrc = await crc32File(entry.fullPath);
      } catch { continue; }
    }

    const dt = dosDateTime(stat ? stat.mtime : new Date());

    // Local file header
    const localHeader = Buffer.concat([
      Buffer.from([0x50, 0x4B, 0x03, 0x04]), // signature
      writeUInt16LE(20),                       // version needed
      writeUInt16LE(0x0800),                   // flags (UTF-8)
      writeUInt16LE(0),                        // compression: stored
      writeUInt16LE(dt.time),
      writeUInt16LE(dt.date),
      writeUInt32LE(fileCrc),
      writeUInt32LE(size),                     // compressed = uncompressed
      writeUInt32LE(size),
      writeUInt16LE(nameBytes.length),
      writeUInt16LE(0),                        // extra field length
      nameBytes,
    ]);

    await write(localHeader);
    // Escribir contenido del archivo en streaming — no carga todo en RAM
    if (!isDir) await streamFileTo(entry.fullPath, out);

    // Central directory entry (guardamos para el final)
    centralDir.push({
      nameBytes,
      crc:  fileCrc,
      size,
      dt,
      offset,
      isDir,
    });

    offset += localHeader.length + size;
    fileCount++;
    parentPort.postMessage({ type: 'progress', done: fileCount, total: allEntries.length });
  }

  // Central directory
  const centralOffset = offset;
  let centralSize = 0;

  for (const cd of centralDir) {
    const entry = Buffer.concat([
      Buffer.from([0x50, 0x4B, 0x01, 0x02]), // signature
      writeUInt16LE(20),                       // version made by
      writeUInt16LE(20),                       // version needed
      writeUInt16LE(0x0800),                   // flags
      writeUInt16LE(0),                        // compression
      writeUInt16LE(cd.dt.time),
      writeUInt16LE(cd.dt.date),
      writeUInt32LE(cd.crc),
      writeUInt32LE(cd.size),
      writeUInt32LE(cd.size),
      writeUInt16LE(cd.nameBytes.length),
      writeUInt16LE(0),                        // extra
      writeUInt16LE(0),                        // comment
      writeUInt16LE(0),                        // disk start
      writeUInt16LE(cd.isDir ? 16 : 0),        // internal attr
      writeUInt32LE(cd.isDir ? 0x10 : 0),      // external attr
      writeUInt32LE(cd.offset),
      cd.nameBytes,
    ]);
    await write(entry);
    centralSize += entry.length;
  }

  // End of central directory
  const eocd = Buffer.concat([
    Buffer.from([0x50, 0x4B, 0x05, 0x06]),
    writeUInt16LE(0), writeUInt16LE(0),
    writeUInt16LE(centralDir.length),
    writeUInt16LE(centralDir.length),
    writeUInt32LE(centralSize),
    writeUInt32LE(centralOffset),
    writeUInt16LE(0),
  ]);
  await write(eocd);

  await new Promise((res, rej) => { out.end(res); out.once('error', rej); });
  parentPort.postMessage({ type: 'done', path: destPath });
}

buildZip().catch(err => parentPort.postMessage({ type: 'error', message: err.message }));
