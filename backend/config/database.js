/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — JSON File Database
 *  A lightweight, file-based database for development.
 *  Stores data in /data/ directory as JSON files.
 * ═══════════════════════════════════════════════════════════════
 */

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', '..', 'data');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

class JsonDB {
  constructor(collectionName) {
    this.filePath = path.join(DATA_DIR, `${collectionName}.json`);
    this.collectionName = collectionName;
    this._ensureFile();
  }

  _ensureFile() {
    if (!fs.existsSync(this.filePath)) {
      fs.writeFileSync(this.filePath, JSON.stringify([], null, 2), 'utf-8');
    }
  }

  _read() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf-8');
      return JSON.parse(raw);
    } catch {
      return [];
    }
  }

  _write(data) {
    fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  /** Find all records matching a query object */
  find(query = {}) {
    const records = this._read();
    return records.filter(record => {
      return Object.keys(query).every(key => record[key] === query[key]);
    });
  }

  /** Find a single record matching a query object */
  findOne(query = {}) {
    const records = this._read();
    return records.find(record => {
      return Object.keys(query).every(key => record[key] === query[key]);
    }) || null;
  }

  /** Find a record by its ID */
  findById(id) {
    return this.findOne({ id });
  }

  /** Insert a new record */
  insert(record) {
    const records = this._read();
    records.push(record);
    this._write(records);
    return record;
  }

  /** Update a record by ID */
  updateById(id, updates) {
    const records = this._read();
    const index = records.findIndex(r => r.id === id);
    if (index === -1) return null;
    records[index] = { ...records[index], ...updates };
    this._write(records);
    return records[index];
  }

  /** Update records matching a query */
  updateOne(query, updates) {
    const records = this._read();
    const index = records.findIndex(record => {
      return Object.keys(query).every(key => record[key] === query[key]);
    });
    if (index === -1) return null;
    records[index] = { ...records[index], ...updates };
    this._write(records);
    return records[index];
  }

  /** Delete a record by ID */
  deleteById(id) {
    const records = this._read();
    const filtered = records.filter(r => r.id !== id);
    this._write(filtered);
    return filtered.length < records.length;
  }

  /** Delete records matching a query */
  deleteMany(query) {
    const records = this._read();
    const filtered = records.filter(record => {
      return !Object.keys(query).every(key => record[key] === query[key]);
    });
    const deletedCount = records.length - filtered.length;
    this._write(filtered);
    return deletedCount;
  }

  /** Count records matching a query */
  count(query = {}) {
    return this.find(query).length;
  }
}

module.exports = JsonDB;
