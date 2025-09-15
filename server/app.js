/* eslint-disable no-unused-vars */
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const fs = require('fs');
// NEW: file upload support
const multer = require('multer');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
// Increase limits so rich HTML content (content field) does not trigger Multer "Field value too long"
// fieldSize: max bytes per text field (HTML content can be large)
// fileSize: max bytes per single file (adjust as needed)
const upload = multer({
  dest: uploadsDir,
  limits: {
    fieldSize: 5 * 1024 * 1024,   // 5MB per text field (content, excerpt, etc.)
    fileSize: 10 * 1024 * 1024,   // 10MB per uploaded file
    files: 30,
    fields: 100
  }
});
// Central Multer error translator
function handleMulterErr(err, req, res, next){
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FIELD_SIZE' || err.code === 'LIMIT_FIELD_VALUE') {
      return res.status(413).json({ error: 'payload_too_large', detail: 'A text field exceeded the allowed size.' });
    }
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'file_too_large', detail: 'Uploaded file is too large.' });
    }
    return res.status(400).json({ error: 'upload_error', code: err.code });
  }
  next(err);
}

const app = express();

// DB setup
const dbPath = path.join(__dirname, 'app.db');
const db = new sqlite3.Database(dbPath);

// Ensure schema
const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
db.exec(schema);
db.run("ALTER TABLE authorized_media ADD COLUMN role TEXT DEFAULT 'resource'", ()=>{}); // ignore error
db.run("ALTER TABLE authorized_lectures ADD COLUMN duration TEXT", ()=>{}); // ignore if exists
db.run("ALTER TABLE authorized_courses ADD COLUMN image_url TEXT", ()=>{}); // ignore if exists
db.run(`CREATE TABLE IF NOT EXISTS blogs(
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  excerpt TEXT,
  content TEXT,
  image_url TEXT,
  author TEXT,
  editor TEXT,
  is_public INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 2 }
}));

// Serve static assets
app.use('/css', express.static(path.join(__dirname, '../css')));
app.use('/js', express.static(path.join(__dirname, '../js')));
app.use('/json', express.static(path.join(__dirname, '../json')));
app.use('/images', express.static(path.join(__dirname, '../images')));
app.use('/uploads', express.static(uploadsDir));

// Simple request logger for debugging 500s
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

// Catch unhandled promise rejections / uncaught exceptions and log to disk
process.on('unhandledRejection', (reason, p) => {
  console.error('Unhandled Rejection at:', p, 'reason:', reason);
  try { fs.appendFileSync(path.join(__dirname, 'error.log'), `${new Date().toISOString()} UNHANDLED_REJECTION ${String(reason)}\n`); } catch (e) {}
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  try { fs.appendFileSync(path.join(__dirname, 'error.log'), `${new Date().toISOString()} UNCAUGHT_EXCEPTION ${err.stack || String(err)}\n`); } catch (e) {}
  // optional: process.exit(1);
});

// Helper middleware
function requireAuth(role) {
  return (req, res, next) => {
    if (!req.session.user) return res.redirect('/login');
    if (role && req.session.user.role !== role) return res.status(403).send('Forbidden');
    next();
  };
}

// Auth routes
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing credentials');
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).send('Server error');
    if (!user) return res.status(401).send('Invalid credentials');
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).send('Invalid credentials');
    req.session.user = { id: user.id, role: user.role, username: user.username };
    if (user.role === 'admin') return res.redirect('/admin');
    return res.redirect('/student');
  });
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, '../register.html'));
});

app.post('/register', async (req, res) => {
  const { username, full_name, father_name, cnic, email, phone, city, password, confirm_password } = req.body;
  if (!username || !full_name || !father_name || !cnic || !email || !phone || !city || !password || !confirm_password)
    return res.status(400).send('All fields required');
  if (password !== confirm_password) return res.status(400).send('Passwords do not match');
  try {
    const hash = await bcrypt.hash(password, 12);
    const id = crypto.randomUUID();
    db.run(`INSERT INTO users (id, role, username, full_name, father_name, cnic, email, phone, city, password_hash) VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [id, 'student', username, full_name, father_name, cnic, email, phone, city, hash], (err) => {
        if (err) {
          if (err.message.includes('UNIQUE')) return res.status(400).send('Username / Email / CNIC already exists');
          return res.status(500).send('Server error');
        }
        res.redirect('/login');
      });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// Protected dashboards (updated)
app.get('/admin', (req, res) => res.redirect('/admin/dashboard'));
app.get('/student', (req, res) => res.redirect('/student/dashboard'));

app.get('/admin/dashboard', requireAuth('admin'), (req, res) => {
  res.sendFile(path.join(__dirname, '../admin/dashboard.html'));
});
app.get('/student/dashboard', requireAuth('student'), (req, res) => {
  res.sendFile(path.join(__dirname, '../student/dashboard.html'));
});

// Admin and student pages
app.get('/admin/students', requireAuth('admin'), (req, res) => { res.sendFile(path.join(__dirname, '../admin/students.html')); });
app.get('/admin/courses', requireAuth('admin'), (req, res) => { res.sendFile(path.join(__dirname, '../admin/courses.html')); });
app.get('/student/profile', requireAuth('student'), (req, res) => { res.sendFile(path.join(__dirname, '../student/profile.html')); });

// Public pages
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, '../index.html')); });
app.get('/courses', (req, res) => { res.sendFile(path.join(__dirname, '../course.html')); });
app.get('/course-detail', (req, res) => { res.sendFile(path.join(__dirname, '../course-detail.html')); });
app.get('/blog', (req, res) => { res.sendFile(path.join(__dirname, '../blog.html')); });
app.get('/blog-detail', (req, res) => { res.sendFile(path.join(__dirname, '../blog-detail.html')); });
app.get('/gallery', (req, res) => { res.sendFile(path.join(__dirname, '../gallery.html')); });
app.get('/contact', (req, res) => { res.sendFile(path.join(__dirname, '../contact.html')); });
app.get('/apply', (req, res) => { res.sendFile(path.join(__dirname, '../apply.html')); });
app.get('/about', (req, res) => { res.sendFile(path.join(__dirname, '../about.html')); });
app.get('/notes', (req,res)=>res.sendFile(path.join(__dirname,'../notes.html')));
app.get('/admin/notes', requireAuth('admin'), (req,res)=>res.sendFile(path.join(__dirname,'../admin/notes.html')));
app.get('/student/notes', requireAuth('student'), (req,res)=>res.sendFile(path.join(__dirname,'../student/notes.html')));

// Student panel course pages (fix 404 for /student/courses & /student/course-detail)
app.get('/student/courses', requireAuth('student'), (req,res)=>{
  res.sendFile(path.join(__dirname,'../student/courses.html'));
});
app.get('/student/course-detail', requireAuth('student'), (req,res)=>{
  res.sendFile(path.join(__dirname,'../student/course-detail.html'));
});

// Admin APIs
app.get('/api/admin/students', requireAuth('admin'), (req, res) => {
  db.all("SELECT id, username, full_name, email, phone, city, created_at, cnic FROM users WHERE role='student'", [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

app.delete('/api/admin/students/:id', requireAuth('admin'), (req, res) => {
  const id = req.params.id;
  db.run('DELETE FROM users WHERE id = ? AND role = ?', [id, 'student'], function (err) {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (this.changes === 0) return res.status(404).json({ error: 'not_found' });
    res.json({ deleted: true });
  });
});

// Courses API - store in json/courses.json
const coursesFile = path.join(__dirname, '../json/courses.json');
app.get('/api/admin/courses', requireAuth('admin'), (req, res) => {
  fs.readFile(coursesFile, 'utf8', (err, data) => {
    if (err) return res.status(500).json({ error: 'file_error' });
    try {
      const arr = JSON.parse(data);
      res.json(arr);
    } catch (e) {
      res.status(500).json({ error: 'parse_error' });
    }
  });
});
app.post('/api/admin/courses', requireAuth('admin'), (req, res) => {
  const { title, description, duration, imageUrl } = req.body;
  if (!title || !description) return res.status(400).json({ error: 'missing_fields' });
  fs.readFile(coursesFile, 'utf8', (err, data) => {
    let arr = [];
    if (!err) {
      try { arr = JSON.parse(data); } catch (e) { arr = []; }
    }
    const newCourse = { id: crypto.randomUUID(), title, description, duration: duration || '', imageUrl: imageUrl || '' };
    arr.push(newCourse);
    fs.writeFile(coursesFile, JSON.stringify(arr, null, 2), (err) => {
      if (err) return res.status(500).json({ error: 'write_error' });
      res.json(newCourse);
    });
  });
});

// NEW: update public course
app.put('/api/admin/courses/:id', requireAuth('admin'), (req, res) => {
  const id = req.params.id;
  const { title, description, duration, imageUrl } = req.body;
  if (!title && !description && imageUrl === undefined) return res.status(400).json({ error: 'missing_fields' });
  fs.readFile(coursesFile, 'utf8', (err, data) => {
    if (err) return res.status(500).json({ error: 'file_error' });
    let arr;
    try { arr = JSON.parse(data); } catch { return res.status(500).json({ error: 'parse_error' }); }
    const idx = arr.findIndex(c => String(c.id) === id);
    if (idx === -1) return res.status(404).json({ error: 'not_found' });
    arr[idx] = { ...arr[idx], title, description, duration: duration || '', imageUrl: imageUrl || arr[idx].imageUrl || '' };
    fs.writeFile(coursesFile, JSON.stringify(arr, null, 2), e => {
      if (e) return res.status(500).json({ error: 'write_error' });
      res.json(arr[idx]);
    });
  });
});

// NEW: delete public course
app.delete('/api/admin/courses/:id', requireAuth('admin'), (req, res) => {
  const id = req.params.id;
  fs.readFile(coursesFile, 'utf8', (err, data) => {
    if (err) return res.status(500).json({ error: 'file_error' });
    let arr;
    try { arr = JSON.parse(data); } catch { return res.status(500).json({ error: 'parse_error' }); }
    const idx = arr.findIndex(c => String(c.id) === id);
    if (idx === -1) return res.status(404).json({ error: 'not_found' });
    arr.splice(idx, 1);
    fs.writeFile(coursesFile, JSON.stringify(arr, null, 2), e => {
      if (e) return res.status(500).json({ error: 'write_error' });
      res.json({ deleted: true });
    });
  });
});

// Student API
app.get('/api/student/me', requireAuth('student'), (req, res) => {
  db.get('SELECT id, username, full_name, father_name, cnic, email, phone, city, created_at FROM users WHERE id = ?', [req.session.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(row);
  });
});

// =============== Authorized Courses (Protected) APIs ===============

// List authorized courses (summary)
app.get('/api/admin/auth-courses', requireAuth('admin'), (req, res) => {
  const sql = `
    SELECT c.id, c.title, c.description, c.image_url,
      (SELECT COUNT(*) FROM authorized_lectures l WHERE l.course_id = c.id) AS lectures
    FROM authorized_courses c
    ORDER BY c.created_at DESC`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

// Get single authorized course (with lectures + media)
app.get('/api/admin/auth-courses/:id', requireAuth('admin'), (req, res) => {
  const courseId = req.params.id;
  db.get('SELECT id,title,description,created_at FROM authorized_courses WHERE id=?',[courseId],(err,course)=>{
    if(err) return res.status(500).json({error:'db_error'});
    if(!course) return res.status(404).json({error:'not_found'});
    const q = `SELECT l.id AS lecture_id,l.title,l.description,l.duration,
      m.id AS media_id,m.type,m.url,m.original_name,m.role
      FROM authorized_lectures l
      LEFT JOIN authorized_media m ON m.lecture_id=l.id
      WHERE l.course_id=? ORDER BY l.created_at,m.created_at`;
    db.all(q,[courseId],(e,rows)=>{
      if(e) return res.status(500).json({error:'db_error'});
      const map = new Map();
      rows.forEach(r=>{
        if(!map.has(r.lecture_id)){
          map.set(r.lecture_id,{id:r.lecture_id,title:r.title,description:r.description||'',duration:r.duration||'',main:null,support:[],resources:[]});
        }
        if(r.media_id){
          const tgt = map.get(r.lecture_id);
          if(r.role==='main') tgt.main = {id:r.media_id,url:r.url,name:r.original_name,role:r.role,type:r.type};
          else if(r.role==='support') tgt.support.push({id:r.media_id,url:r.url,name:r.original_name,role:r.role,type:r.type});
          else tgt.resources.push({id:r.media_id,url:r.url,name:r.original_name,role:r.role,type:r.type});
        }
      });
      course.lectures = Array.from(map.values());
      res.json(course);
    });
  });
});

// Create authorized course
app.post('/api/admin/auth-courses', requireAuth('admin'), (req, res) => {
  const { title, description, imageUrl } = req.body;
  if (!title || !description) return res.status(400).json({ error: 'missing_fields' });
  const id = crypto.randomUUID();
  db.run('INSERT INTO authorized_courses (id, title, description, image_url) VALUES (?,?,?,?)',
    [id, title, description, imageUrl || ''],
    err => {
      if (err) return res.status(500).json({ error: 'db_error' });
      res.json({ id, title, description, image_url: imageUrl || '' });
    });
});

// NEW: update authorized course metadata
app.put('/api/admin/auth-courses/:id', requireAuth('admin'), (req, res) => {
  const id = req.params.id;
  const { title, description, imageUrl } = req.body;
  if (!title && !description && imageUrl === undefined) return res.status(400).json({ error: 'missing_fields' });
  db.run(
    'UPDATE authorized_courses SET title = COALESCE(?, title), description = COALESCE(?, description), image_url = COALESCE(?, image_url) WHERE id = ?',
    [title || null, description || null, imageUrl !== undefined ? imageUrl : null, id],
    function (err) {
      if (err) return res.status(500).json({ error: 'db_error' });
      if (this.changes === 0) return res.status(404).json({ error: 'not_found' });
      db.get('SELECT id, title, description, image_url, created_at FROM authorized_courses WHERE id = ?', [id], (e, row) => {
        if (e) return res.status(500).json({ error: 'db_error' });
        res.json(row);
      });
    }
  );
});

// Delete authorized course (cascade lectures & media)
app.delete('/api/admin/auth-courses/:id', requireAuth('admin'), (req, res) => {
  db.run('DELETE FROM authorized_courses WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (this.changes === 0) return res.status(404).json({ error: 'not_found' });
    res.json({ deleted: true });
  });
});

// Create authorized course lecture (add duration support)
app.post('/api/admin/auth-courses/:id/lectures', requireAuth('admin'), (req, res) => {
  const { title, description, duration } = req.body;
  if (!title) return res.status(400).json({ error: 'missing_title' });
  const lectureId = crypto.randomUUID();
  db.run(
    'INSERT INTO authorized_lectures (id, course_id, title, description, duration) VALUES (?,?,?,?,?)',
    [lectureId, req.params.id, title, description || '', duration || ''],
    err => {
      if (err) return res.status(500).json({ error: 'db_error' });
      res.json({ id: lectureId, course_id: req.params.id, title, description: description || '', duration: duration || '' });
    }
  );
});

// NEW: update authorized lecture
app.put('/api/admin/auth-lectures/:lectureId', requireAuth('admin'), (req,res)=>{
  const { title, description, duration } = req.body;
  db.run(
    'UPDATE authorized_lectures SET title=COALESCE(?,title), description=COALESCE(?,description), duration=COALESCE(?,duration) WHERE id=?',
    [title, description, duration, req.params.lectureId],
    function(err){
      if(err) return res.status(500).json({error:'db_error'});
      if(this.changes===0) return res.status(404).json({error:'not_found'});
      db.get('SELECT id, title, description, duration FROM authorized_lectures WHERE id=?',[req.params.lectureId],(e,row)=>{
        if(e) return res.status(500).json({error:'db_error'});
        res.json(row);
      });
    }
  );
});

// NEW: delete authorized lecture
app.delete('/api/admin/auth-lectures/:lectureId', requireAuth('admin'), (req,res)=>{
  db.run('DELETE FROM authorized_lectures WHERE id=?',[req.params.lectureId], function(err){
    if(err) return res.status(500).json({error:'db_error'});
    if(this.changes===0) return res.status(404).json({error:'not_found'});
    res.json({deleted:true});
  });
});

// NEW: delete authorized media item
app.delete('/api/admin/auth-media/:mediaId', requireAuth('admin'), (req,res)=>{
  db.run('DELETE FROM authorized_media WHERE id=?',[req.params.mediaId], function(err){
    if(err) return res.status(500).json({error:'db_error'});
    if(this.changes===0) return res.status(404).json({error:'not_found'});
    res.json({deleted:true});
  });
});

// GET single public course (used by admin UI)
app.get('/api/admin/courses/:id', requireAuth('admin'), (req, res) => {
  const id = req.params.id;
  fs.readFile(coursesFile, 'utf8', (err, data) => {
    if (err) return res.status(500).json({ error: 'file_error' });
    let arr;
    try { arr = JSON.parse(data || '[]'); } catch (e) { return res.status(500).json({ error: 'parse_error' }); }
    const course = arr.find(c => String(c.id) === String(id));
    if (!course) return res.status(404).json({ error: 'not_found' });
    res.json(course);
  });
});

// Ensure notes categories endpoint is defined (single definition before 404)
app.get('/api/admin/notes/categories', requireAuth('admin'), (req, res) => {
  db.all("SELECT id,parent_id,name FROM notes_categories ORDER BY name", [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

// Ensure admin notes list endpoint is defined before the 404 handler
app.get('/api/admin/notes', requireAuth('admin'), (req, res) => {
  const isPublic = req.query.is_public;
  let sql = "SELECT n.*, c.name as category_name FROM notes n LEFT JOIN notes_categories c ON c.id=n.category_id";
  const params = [];
  if (isPublic === '1' || isPublic === '0') {
    sql += " WHERE n.is_public = ?";
    params.push(isPublic);
  }
  sql += " ORDER BY n.created_at DESC";
  db.all(sql, params, (e, rows) => {
    if (e) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

// ===== Blog Page Routes (must be before 404) =====
app.get('/admin/blogs', requireAuth('admin'), (req,res)=>res.sendFile(path.join(__dirname,'../admin/blogs.html')));
app.get('/student/blogs', requireAuth('student'), (req,res)=>res.sendFile(path.join(__dirname,'../student/blogs.html')));

// ===== Blog APIs =====

// Admin list (optional ?is_public=1|0)
app.get('/api/admin/blogs', requireAuth('admin'), (req,res)=>{
  const f = req.query.is_public;
  let sql = "SELECT id,title,excerpt,image_url,author,editor,is_public,created_at FROM blogs";
  const params=[];
  if(f==='0'||f==='1'){ sql+=" WHERE is_public=?"; params.push(f); }
  sql+=" ORDER BY created_at DESC";
  db.all(sql, params, (e,rows)=>{ if(e) return res.status(500).json({error:'db_error'}); res.json(rows); });
});

// Admin get single
app.get('/api/admin/blogs/:id', requireAuth('admin'), (req,res)=>{
  db.get("SELECT * FROM blogs WHERE id=?", [req.params.id], (e,row)=>{
    if(e) return res.status(500).json({error:'db_error'});
    if(!row) return res.status(404).json({error:'not_found'});
    res.json(row);
  });
});

// Admin create
const blogUploadSingle = upload.single('image');
app.post('/api/admin/blogs', requireAuth('admin'), (req, res, next) => {
  blogUploadSingle(req, res, (err) => {
    if (err) return handleMulterErr(err, req, res, next);
    try {
      const { title, excerpt, content, author, editor, is_public } = req.body;
      if (!title || !content) return res.status(400).json({ error: 'missing_fields' });
      const publicFlag = (is_public === '0' ? 0 : 1);
      const uploadUrl = req.file ? '/uploads/' + path.basename(req.file.path) : (req.body.image_url || '');
      if (publicFlag === 1) {
        // Store in JSON file (public source of truth)
        readPublicBlogs((errR, arr) => {
          if (errR) return res.status(500).json({ error: 'file_error' });
            const numericIds = arr.map(p => typeof p.id === 'number' ? p.id : null).filter(v => v !== null);
            const nextNumeric = numericIds.length ? Math.max(...numericIds) + 1 : 1;
            const newId = nextNumeric;
            const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
            arr.push({
              id: newId,
              title,
              author: author || 'Staff',
              date: dateStr,
              excerpt: excerpt || '',
              imageUrl: uploadUrl,
              content
            });
            writePublicBlogs(arr, (wErr) => {
              if (wErr) return res.status(500).json({ error: 'write_error' });
              return res.json({
                id: newId,
                title,
                excerpt: excerpt || '',
                image_url: uploadUrl,
                author: author || 'Staff',
                editor: editor || '',
                is_public: 1
              });
            });
        });
      } else {
        // Authorized blog -> store in DB only
        const id = crypto.randomUUID();
        db.run(`INSERT INTO blogs (id,title,excerpt,content,image_url,author,editor,is_public) VALUES (?,?,?,?,?,?,?,?)`,
          [id, title, excerpt || '', content, uploadUrl, author || '', editor || '', 0],
          errDb => {
            if (errDb) return res.status(500).json({ error: 'db_error' });
            res.json({ id, title, excerpt: excerpt || '', image_url: uploadUrl, author: author || '', editor: editor || '', is_public: 0 });
          });
      }
    } catch (ex) { next(ex); }
  });
});

// Admin update (wrapped for Multer error handling)
app.put('/api/admin/blogs/:id', requireAuth('admin'), (req, res, next) => {
  blogUploadSingle(req, res, (err) => {
    if (err) return handleMulterErr(err, req, res, next);
    try {
      const { title, excerpt, content, author, editor, is_public } = req.body;
      const sets = []; const params = [];
      if (title !== undefined) { sets.push('title=?'); params.push(title); }
      if (excerpt !== undefined) { sets.push('excerpt=?'); params.push(excerpt); }
      if (content !== undefined) { sets.push('content=?'); params.push(content); }
      if (author !== undefined) { sets.push('author=?'); params.push(author); }
      if (editor !== undefined) { sets.push('editor=?'); params.push(editor); }
      if (is_public === '0' || is_public === '1') { sets.push('is_public=?'); params.push(is_public); }
      if (req.file) { sets.push('image_url=?'); params.push('/uploads/' + path.basename(req.file.path)); }
      if (!sets.length) return res.status(400).json({ error: 'nothing_to_update' });
      params.push(req.params.id);
      db.run(`UPDATE blogs SET ${sets.join(', ')} WHERE id=?`, params, function (errU) {
        if (errU) return res.status(500).json({ error: 'db_error' });
        if (this.changes === 0) return res.status(404).json({ error: 'not_found' });
        db.get('SELECT * FROM blogs WHERE id=?', [req.params.id], (e, row) => {
          if (e) return res.status(500).json({ error: 'db_error' });
          res.json(row);
        });
      });
    } catch (ex) { next(ex); }
  });
});

// Admin delete
app.delete('/api/admin/blogs/:id', requireAuth('admin'), (req,res)=>{
  db.run("DELETE FROM blogs WHERE id=?", [req.params.id], function(err){
    if(err) return res.status(500).json({error:'db_error'});
    if(this.changes===0) return res.status(404).json({error:'not_found'});
    res.json({deleted:true});
  });
});

// Public JSON file path and helpers
const blogsJsonFile = path.join(__dirname, '../json/blogs.json');
function readPublicBlogs(cb){
  fs.readFile(blogsJsonFile,'utf8',(err,data)=>{
    if(err){
      if(err.code==='ENOENT') return cb(null, []);
      console.error('readPublicBlogs read error', err);
      try { fs.appendFileSync(path.join(__dirname, 'error.log'), `${new Date().toISOString()} readPublicBlogs read error: ${err.stack||err}\n`); } catch(e){}
      return cb(err);
    }
    try {
      const parsed = JSON.parse(data || '[]');
      return cb(null, parsed);
    } catch (parseErr) {
      console.error('readPublicBlogs JSON parse error', parseErr);
      try { fs.appendFileSync(path.join(__dirname, 'error.log'), `${new Date().toISOString()} readPublicBlogs parse error: ${parseErr.stack||parseErr}\n`); } catch(e){}
      // Recover by returning empty array to avoid 500 due to parse failures
      return cb(null, []);
    }
  });
}
function writePublicBlogs(arr, cb){
	fs.writeFile(blogsJsonFile, JSON.stringify(arr, null, 2), cb);
}

// Public list (read from JSON file) - used by blog listing page
app.get('/api/blogs/public', (req, res) => {
  readPublicBlogs((err, arr)=>{
    if(err) return res.status(500).json({ error: 'file_error' });
    const mapped = arr.map(p=>({
      id: p.id,
      title: p.title,
      excerpt: p.excerpt || '',
      image_url: p.imageUrl || '',
      author: p.author || 'Staff',
      created_at: p.date || ''
    }));
    res.json(mapped);
  });
});

// Admin: update a public JSON blog (supports optional image upload)
app.put('/api/blogs/public/:id', requireAuth('admin'), upload.single('image'), (req, res) => {
  const id = req.params.id;
  const { title, excerpt, content, author } = req.body;
  readPublicBlogs((err, arr) => {
    if (err) return res.status(500).json({ error: 'file_error' });
    const idx = arr.findIndex(p => String(p.id) === String(id));
    if (idx === -1) return res.status(404).json({ error: 'not_found' });
    const post = arr[idx];
    if (title !== undefined) post.title = title;
    if (excerpt !== undefined) post.excerpt = excerpt;
    if (content !== undefined) post.content = content;
    if (author !== undefined) post.author = author;
    if (req.file) post.imageUrl = '/uploads/' + path.basename(req.file.path);
    // optionally update date to now
    post.date = new Date().toLocaleDateString('en-US',{ year:'numeric', month:'long', day:'numeric'});
    arr[idx] = post;
    writePublicBlogs(arr, (wErr) => {
      if (wErr) return res.status(500).json({ error: 'write_error' });
      res.json({
        id: post.id,
        title: post.title,
        excerpt: post.excerpt || '',
        content: post.content || '',
        image_url: post.imageUrl || '',
        author: post.author || 'Staff',
        created_at: post.date || ''
      });
    });
  });
});

// Admin: delete a public JSON blog
app.delete('/api/blogs/public/:id', requireAuth('admin'), (req, res) => {
  const id = req.params.id;
  readPublicBlogs((err, arr) => {
    if (err) return res.status(500).json({ error: 'file_error' });
    const idx = arr.findIndex(p => String(p.id) === String(id));
    if (idx === -1) return res.status(404).json({ error: 'not_found' });
    arr.splice(idx, 1);
    writePublicBlogs(arr, (wErr) => {
      if (wErr) return res.status(500).json({ error: 'write_error' });
      res.json({ deleted: true });
    });
  });
});

// Public single (ensure this exists and reads from json/blogs.json)
app.get('/api/blogs/public/:id', (req, res) => {
  readPublicBlogs((err, arr) => {
    if (err) return res.status(500).json({ error: 'file_error' });
    const post = arr.find(p => String(p.id) === String(req.params.id));
    if (!post) return res.status(404).json({ error: 'not_found' });
    res.json({
      id: post.id,
      title: post.title,
      excerpt: post.excerpt || '',
      content: post.content || '',
      image_url: post.imageUrl || '',
      author: post.author || 'Staff',
      created_at: post.date || post.created_at || ''
    });
  });
});

// Public Courses endpoints (read from json/courses.json)
// GET /api/courses/public  -> return array of courses
app.get('/api/courses/public', (req, res) => {
  fs.readFile(coursesFile, 'utf8', (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') return res.json([]);
      return res.status(500).json({ error: 'file_error' });
    }
    try {
      const arr = JSON.parse(data || '[]');
      return res.json(arr);
    } catch (e) {
      console.error('parse courses.json', e);
      return res.status(500).json({ error: 'parse_error' });
    }
  });
});

// GET /api/courses/public/:id -> return single course or 404
app.get('/api/courses/public/:id', (req, res) => {
  const id = req.params.id;
  fs.readFile(coursesFile, 'utf8', (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') return res.status(404).json({ error: 'not_found' });
      return res.status(500).json({ error: 'file_error' });
    }
    try {
      const arr = JSON.parse(data || '[]');
      const course = arr.find(c => String(c.id) === String(id));
      if (!course) return res.status(404).json({ error: 'not_found' });
      return res.json(course);
    } catch (e) {
      console.error('parse courses.json', e);
      return res.status(500).json({ error: 'parse_error' });
    }
  });
});

// Student notes (only is_public=1)
app.get('/api/notes/public', (req,res)=>{
  db.all("SELECT n.*, c.name as category_name FROM notes n LEFT JOIN notes_categories c ON c.id=n.category_id WHERE n.is_public=1 ORDER BY n.created_at DESC",[],(e,rows)=>{
    if(e) return res.status(500).json({error:'db_error'}); res.json(rows);
  });
});

// Student notes (both public + authorized)
app.get('/api/student/notes', requireAuth('student'), (req,res)=>{
  db.all("SELECT n.*, c.name as category_name FROM notes n LEFT JOIN notes_categories c ON c.id=n.category_id ORDER BY n.created_at DESC",[],(e,rows)=>{
    if(e) return res.status(500).json({error:'db_error'}); res.json(rows);
  });
});

// Student blogs endpoint (authorized + public flag from DB) - used by student UI
app.get('/api/student/blogs', requireAuth('student'), (req, res) => {
  const sql = "SELECT id, title, excerpt, image_url, author, editor, is_public, created_at FROM blogs ORDER BY created_at DESC";
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    // rows already include is_public; return as-is so client can filter authorized posts (is_public===0)
    res.json(rows);
  });
});

// ===== Adjust Public Courses Media Upload to support roles =====
app.post('/api/admin/courses/:courseId/lectures/:lectureId/media',
  requireAuth('admin'),
  upload.array('media', 20),
  (req,res)=>{
    const { mediaRole } = req.body; // 'main' | 'support' | 'resource'
    if(!['main','support','resource'].includes(mediaRole||'')) return res.status(400).json({error:'invalid_role'});
    readPublicCourses((err, arr)=>{
      if(err) return res.status(500).json({error:'file_error'});
      const course = findCourse(arr, req.params.courseId);
      if(!course) return res.status(404).json({error:'course_not_found'});
      const lec = (course.lectures||[]).find(l=>l.id===req.params.lectureId);
      if(!lec) return res.status(404).json({error:'lecture_not_found'});
      // Ensure new structure
      lec.mainVideo = lec.mainVideo || null;
      lec.supportingVideos = lec.supportingVideos || [];
      lec.resources = lec.resources || [];
      const added = [];
      (req.files||[]).forEach(f=>{
        const id = crypto.randomUUID();
        const url = '/uploads/' + path.basename(f.path);
        if(mediaRole==='main'){
          // replace existing main (if any becomes supporting)
            if(lec.mainVideo){
              lec.supportingVideos.push({...lec.mainVideo, promotedFrom:'main'});
            }
            lec.mainVideo = { id, url, name: f.originalname };
            added.push({ id, url, type:'main' });
        } else if(mediaRole==='support'){
          lec.supportingVideos.push({ id, url, name: f.originalname });
          added.push({ id, url, type:'support' });
        } else {
          const ext = (path.extname(f.originalname).replace('.','')||'FILE').toUpperCase();
          lec.resources.push({ id, url, name: f.originalname, type: ext });
          added.push({ id, url, type:'resource' });
        }
      });
      writePublicCourses(arr, e=>{
        if(e) return res.status(500).json({error:'write_error'});
        res.json({added});
      });
    });
  }
);

// ===== Adjust Authorized Courses media upload (role) =====
app.post('/api/admin/auth-lectures/:lectureId/media',
  requireAuth('admin'),
  upload.fields([{ name:'videos', maxCount:20 }, { name:'files', maxCount:40 }]),
  (req,res)=>{
    const role = req.body.mediaRole; // 'main'|'support'|'resource'
    const allowed = ['main','support','resource'];
    const chosenRole = allowed.includes(role)?role:'resource';
    const lectureId = req.params.lectureId;
    const inserts = [];
    const stmt = db.prepare('INSERT INTO authorized_media (id, lecture_id, type, url, original_name, role) VALUES (?,?,?,?,?,?)');
    function addFiles(arr, baseType){
      if(!arr) return;
      arr.forEach(f=>{
        const id = crypto.randomUUID();
        const url = '/uploads/' + path.basename(f.path);
        stmt.run(id, lectureId, baseType, url, f.originalname, chosenRole);
        inserts.push({ id, type:baseType, url, name:f.originalname, role:chosenRole });
      });
    }
    addFiles(req.files['videos'],'video');
    addFiles(req.files['files'],'file');
    stmt.finalize(err=>{
      if(err) return res.status(500).json({error:'db_error'});
      // If main role ensure only one main video/file kept (optional simple rule)
      if(chosenRole==='main'){
        db.all("SELECT id FROM authorized_media WHERE lecture_id=? AND role='main' ORDER BY created_at DESC", [lectureId], (e,rows)=>{
          if(!e && rows.length>1){
            const toDemote = rows.slice(1).map(r=>r.id);
            if(toDemote.length){
              const qs = toDemote.map(()=>'?').join(',');
              db.run(`UPDATE authorized_media SET role='support' WHERE id IN (${qs})`, toDemote);
            }
          }
          res.json({added:inserts});
        });
      } else res.json({added:inserts});
    });
  }
);

// ===== Adjust single authorized course fetch to group by role =====
app.get('/api/admin/auth-courses/:id', requireAuth('admin'), (req,res)=>{
  const courseId = req.params.id;
  db.get('SELECT id,title,description,created_at FROM authorized_courses WHERE id=?',[courseId],(err,course)=>{
    if(err) return res.status(500).json({error:'db_error'});
    if(!course) return res.status(404).json({error:'not_found'});
    const q = `SELECT l.id AS lecture_id,l.title,l.description,
      m.id AS media_id,m.type,m.url,m.original_name,m.role
      FROM authorized_lectures l
      LEFT JOIN authorized_media m ON m.lecture_id=l.id
      WHERE l.course_id=? ORDER BY l.created_at,m.created_at`;
    db.all(q,[courseId],(e,rows)=>{
      if(e) return res.status(500).json({error:'db_error'});
      const map = new Map();
      rows.forEach(r=>{
        if(!map.has(r.lecture_id)){
          map.set(r.lecture_id,{id:r.lecture_id,title:r.title,description:r.description||'',main:null,support:[],resources:[]});
        }
        if(r.media_id){
          const target = map.get(r.lecture_id);
          if(r.role==='main') target.main = {id:r.media_id,url:r.url,name:r.original_name,role:r.role,type:r.type};
          else if(r.role==='support') target.support.push({id:r.media_id,url:r.url,name:r.original_name,role:r.role,type:r.type});
          else target.resources.push({id:r.media_id,url:r.url,name:r.original_name,role:r.role,type:r.type});
        }
      });
      course.lectures = Array.from(map.values());
      res.json(course);
    });
  });
});

// ===== Adjust public lecture media deletion endpoints to handle new structure =====
app.delete('/api/admin/courses/:courseId/lectures/:lectureId/videos/:mediaId', requireAuth('admin'), (req,res)=>{
  readPublicCourses((err,arr)=>{
    if(err) return res.status(500).json({error:'file_error'});
    const course=findCourse(arr,req.params.courseId); if(!course) return res.status(404).json({error:'course_not_found'});
    const lec=(course.lectures||[]).find(l=>l.id===req.params.lectureId); if(!lec) return res.status(404).json({error:'lecture_not_found'});
    lec.mainVideo = (lec.mainVideo && lec.mainVideo.id===req.params.mediaId)?null:lec.mainVideo;
    const before = lec.supportingVideos?.length||0;
    lec.supportingVideos = (lec.supportingVideos||[]).filter(v=>v.id!==req.params.mediaId);
    if(before===lec.supportingVideos.length && (!lec.mainVideo || lec.mainVideo.id!==req.params.mediaId))
      return res.status(404).json({error:'media_not_found'});
    writePublicCourses(arr,e=>{
      if(e) return res.status(500).json({error:'write_error'});
      res.json({deleted:true});
    });
  });
});

// ===== MOVE: helper functions + student endpoints HERE (before 404 and listen) =====
function readPublicCourses(cb){
  fs.readFile(coursesFile,'utf8',(err,data)=>{
    if(err){
      if(err.code === 'ENOENT') return cb(null, []);
      console.error('readPublicCourses read error', err);
      try { fs.appendFileSync(path.join(__dirname, 'error.log'), `${new Date().toISOString()} readPublicCourses read error: ${err.stack||err}\n`); } catch(e){}
      return cb(err);
    }
    try {
      const arr = JSON.parse(data || '[]');
      cb(null, arr);
    } catch (parseErr) {
      console.error('readPublicCourses JSON parse error', parseErr);
      try { fs.appendFileSync(path.join(__dirname, 'error.log'), `${new Date().toISOString()} readPublicCourses parse error: ${parseErr.stack||parseErr}\n`); } catch(e){}
      // Recover by returning empty array
      cb(null, []);
    }
  });
}
function writePublicCourses(arr, cb){
  fs.writeFile(coursesFile, JSON.stringify(arr, null, 2), cb);
}
function findCourse(arr, id){
  return arr.find(c=>String(c.id)===String(id));
}

// Student endpoints for authorized courses (must be defined before 404)
app.get('/api/student/auth-courses', requireAuth('student'), (req,res)=>{
  const sql = `
    SELECT c.id, c.title, c.description, c.image_url,
      (SELECT COUNT(*) FROM authorized_lectures l WHERE l.course_id=c.id) AS lectures
    FROM authorized_courses c ORDER BY c.created_at DESC`;
  db.all(sql, [], (err, rows)=>{
    if(err) return res.status(500).json({error:'db_error'});
    res.json(rows);
  });
});

app.get('/api/student/auth-courses/:id', requireAuth('student'), (req,res)=>{
  const courseId = req.params.id;
  db.get('SELECT id,title,description,image_url FROM authorized_courses WHERE id=?',[courseId],(err,course)=>{
    if(err) return res.status(500).json({error:'db_error'});
    if(!course) return res.status(404).json({error:'not_found'});
    const q = `SELECT l.id AS lecture_id,l.title,l.description,l.duration,
      m.id AS media_id,m.type,m.url,m.original_name,m.role
      FROM authorized_lectures l
      LEFT JOIN authorized_media m ON m.lecture_id=l.id
      WHERE l.course_id=? ORDER BY l.created_at,m.created_at`;
    db.all(q,[courseId],(e,rows)=>{
      if(e) return res.status(500).json({error:'db_error'});
      const map=new Map();
      rows.forEach(r=>{
        if(!map.has(r.lecture_id)){
          map.set(r.lecture_id,{id:r.lecture_id,title:r.title,description:r.description||'',duration:r.duration||'',mainVideo:null,supportingVideos:[],resources:[]});
        }
        if(r.media_id){
          const tgt = map.get(r.lecture_id);
          if(r.role==='main') tgt.mainVideo = {id:r.media_id,url:r.url,name:r.original_name,type:r.type};
          else if(r.role==='support') tgt.supportingVideos.push({id:r.media_id,url:r.url,name:r.original_name,type:r.type});
          else tgt.resources.push({id:r.media_id,url:r.url,name:r.original_name,type:r.type});
        }
      });
      course.lectures = Array.from(map.values());
      res.json(course);
    });
  });
});
// ===== END MOVE =====

// Admin: create notes category
app.post('/api/admin/notes/categories', requireAuth('admin'), express.json(), (req, res) => {
  const { name, parent_id } = req.body || {};
  if (!name) return res.status(400).json({ error: 'missing_name' });
  const id = crypto.randomUUID();
  db.run('INSERT INTO notes_categories (id, parent_id, name) VALUES (?,?,?)', [id, parent_id || null, name], function(err){
    if (err) return res.status(500).json({ error: 'db_error' });
    db.get('SELECT id, parent_id, name FROM notes_categories WHERE id = ?', [id], (e,row)=>{
      if (e) return res.status(500).json({ error: 'db_error' });
      res.json(row);
    });
  });
});

// Admin: upload a note (multipart/form-data)
// expects fields: title, description, category_id, is_public and file input named "file"
app.post('/api/admin/notes', requireAuth('admin'), upload.single('file'), (req, res) => {
  const { title, description, category_id, is_public } = req.body;
  if (!title) return res.status(400).json({ error: 'missing_title' });
  const id = crypto.randomUUID();
  const fileUrl = req.file ? '/uploads/' + path.basename(req.file.path) : (req.body.file_url || '');
  const pub = (is_public === '0' ? 0 : 1);
  db.run('INSERT INTO notes (id, title, description, file_url, category_id, is_public) VALUES (?,?,?,?,?,?)',
    [id, title, description || '', fileUrl, category_id || null, pub],
    function(err){
      if (err) return res.status(500).json({ error: 'db_error' });
      db.get('SELECT n.*, c.name as category_name FROM notes n LEFT JOIN notes_categories c ON c.id=n.category_id WHERE n.id=?', [id], (e,row)=>{
        if (e) return res.status(500).json({ error: 'db_error' });
        res.json(row);
      });
    });
});

// Admin: delete a note (ensure exists)
app.delete('/api/admin/notes/:id', requireAuth('admin'), (req, res) => {
  const id = req.params.id;
  db.get('SELECT file_url FROM notes WHERE id = ?', [id], (err,row)=>{
    if (err) return res.status(500).json({ error: 'db_error' });
    db.run('DELETE FROM notes WHERE id = ?', [id], function(e){
      if (e) return res.status(500).json({ error: 'db_error' });
      if (this.changes === 0) return res.status(404).json({ error: 'not_found' });
      // optional: delete uploaded file from disk
      if (row && row.file_url && row.file_url.startsWith('/uploads/')) {
        const fpath = path.join(uploadsDir, path.basename(row.file_url));
        fs.unlink(fpath, ()=>{}); // ignore unlink errors
      }
      res.json({ deleted: true });
    });
  });
});

// Express error handler: log stack and respond with safe message
app.use((err, req, res, next) => {
  console.error('Express error handler:', err && err.stack ? err.stack : err);
  try { fs.appendFileSync(path.join(__dirname, 'error.log'), `${new Date().toISOString()} EXPRESS_ERROR ${err && err.stack ? err.stack : String(err)}\n`); } catch(e){}
  if (req.xhr || req.headers.accept?.includes('json')) return res.status(500).json({ error: 'internal_server_error', message: err?.message || 'Server error' });
  res.status(500).send('Internal Server Error');
});

// 404
app.use((req, res) => { res.status(404).send('Page Not Found'); });

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
