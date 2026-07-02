const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function crc32(data) {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function dosTime(date) {
  const d = date || new Date();
  return (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >>> 1);
}

function dosDate(date) {
  const d = date || new Date();
  return ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
}

function createZip(files) {
  const localHeaders = [];
  const centralHeaders = [];
  const fileContents = [];
  let offset = 0;

  for (const { name, data } of files) {
    const compressed = zlib.deflateRawSync(data);
    const crc = crc32(data);
    const nameBuf = Buffer.from(name, 'utf-8');

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(8, 8);
    localHeader.writeUInt16LE(dosTime(), 10);
    localHeader.writeUInt16LE(dosDate(), 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    localHeaders.push(Buffer.concat([localHeader, nameBuf]));
    fileContents.push(compressed);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(8, 10);
    centralHeader.writeUInt16LE(dosTime(), 12);
    centralHeader.writeUInt16LE(dosDate(), 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(data.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);

    centralHeaders.push(Buffer.concat([centralHeader, nameBuf]));
    offset += 30 + nameBuf.length + compressed.length;
  }

  const centralStart = offset;
  const central = Buffer.concat(centralHeaders);
  const centralEnd = Buffer.alloc(22);
  centralEnd.writeUInt32LE(0x06054b50, 0);
  centralEnd.writeUInt16LE(0, 4);
  centralEnd.writeUInt16LE(0, 6);
  centralEnd.writeUInt16LE(files.length, 8);
  centralEnd.writeUInt16LE(files.length, 10);
  centralEnd.writeUInt32LE(central.length, 12);
  centralEnd.writeUInt32LE(centralStart, 16);
  centralEnd.writeUInt16LE(0, 20);

  const parts = [];
  for (let i = 0; i < localHeaders.length; i++) {
    parts.push(localHeaders[i]);
    parts.push(fileContents[i]);
  }
  parts.push(central);
  parts.push(centralEnd);

  return Buffer.concat(parts);
}

function createZipFromDir(dir, filePrefix) {
  const files = [];
  const entries = fs.readdirSync(dir);
  for (const entry of entries) {
    const fullPath = path.join(dir, entry);
    const stat = fs.statSync(fullPath);
    if (stat.isFile()) {
      const data = fs.readFileSync(fullPath);
      files.push({ name: (filePrefix || '') + entry, data });
    }
  }
  return createZip(files);
}

module.exports = { createZip, createZipFromDir };
