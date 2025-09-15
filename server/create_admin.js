const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const dbPath = path.join(__dirname, 'app.db');
const db = new sqlite3.Database(dbPath);

const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
db.exec(schema);

async function createAdmin({ username, password, full_name = 'Admin User', father_name = 'N/A', cnic = '00000-0000000-0', email = 'admin@example.com', phone = '00000000000', city = 'Islamabad' }) {
  const hash = await bcrypt.hash(password, 12);
  const id = crypto.randomUUID();
  db.run(`INSERT INTO users (id, role, username, full_name, father_name, cnic, email, phone, city, password_hash) VALUES (?,?,?,?,?,?,?,?,?,?)`,
    [id, 'admin', username, full_name, father_name, cnic, email, phone, city, hash], (err) => {
      if (err) {
        console.error('Error creating admin:', err.message);
        process.exit(1);
      }
      console.log('Admin user created successfully.');
      process.exit(0);
    });
}

const [,, u, p] = process.argv;
if (!u || !p) {
  console.log('Usage: node create_admin.js <username> <password>');
  process.exit(0);
}
createAdmin({ username: u, password: p });
