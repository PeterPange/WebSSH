'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function parseCookies(header) {
  const cookies = Object.create(null);
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    try { cookies[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* malformed cookie is not authentication */ }
  }
  return cookies;
}
function allowedOrigin(req, configured = process.env.WEBSSH_ALLOWED_ORIGINS || '') {
  if (!req.headers.origin) return !['cross-site', 'same-site'].includes(req.headers['sec-fetch-site']);
  try {
    const origin = new URL(req.headers.origin);
    if (!['http:', 'https:'].includes(origin.protocol) || origin.origin !== req.headers.origin) return false;
    const allowed = configured.split(',').map(s => s.trim()).filter(Boolean);
    if (allowed.length) return allowed.includes(origin.origin);
    const protocol = req.socket?.encrypted || req.protocol === 'https' || process.env.WEBSSH_SECURE_COOKIE === '1' ? 'https:' : 'http:';
    return origin.protocol === protocol && origin.host.toLowerCase() === String(req.headers.host || '').toLowerCase();
  } catch { return false; }
}
class RateLimiter {
  constructor(maxEntries = 10000) { this.entries = new Map(); this.maxEntries = maxEntries; }
  take(key, limit, windowMs, now = Date.now()) {
    let entry = this.entries.get(key);
    if (!entry || entry.until <= now) {
      if (this.entries.size >= this.maxEntries) {
        for (const [k, v] of this.entries) if (v.until <= now) this.entries.delete(k);
        if (this.entries.size >= this.maxEntries) return false;
      }
      entry = { count: 0, until: now + windowMs }; this.entries.set(key, entry);
    }
    return ++entry.count <= limit;
  }
}
function createVault(directory, hasEncryptedRows) {
  const keyPath = path.join(directory, 'credentials.key');
  if (!fs.existsSync(keyPath)) {
    if (hasEncryptedRows) throw new Error('Encrypted credentials exist but credentials.key is missing. Restore the key backup.');
    fs.writeFileSync(keyPath, crypto.randomBytes(32), { mode: 0o600, flag: 'wx' });
  }
  fs.chmodSync(keyPath, 0o600);
  const key = fs.readFileSync(keyPath);
  if (key.length !== 32) throw new Error('Invalid credential encryption key');
  return {
    seal(value) {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
      return 'enc:v1:' + Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64');
    },
    open(value) {
      if (!value.startsWith('enc:v1:')) throw new Error('Unencrypted credential record');
      const data = Buffer.from(value.slice(7), 'base64');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
      decipher.setAuthTag(data.subarray(12, 28));
      return JSON.parse(Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8'));
    },
  };
}
function dimensions(value, fallback) {
  const n = Number(value);
  return Number.isInteger(n) && n >= 2 && n <= 500 ? n : fallback;
}
function expireAuthSessions(entries, closeSessions, now = Date.now()) {
  for (const [token, entry] of entries) {
    if (entry.expiresAt <= now) { entries.delete(token); closeSessions(token); }
  }
}
module.exports = { expireAuthSessions, parseCookies, allowedOrigin, RateLimiter, createVault, dimensions };
