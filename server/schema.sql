-- Users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK(role IN ('admin','student')),
  username TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  father_name TEXT NOT NULL,
  cnic TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL,
  city TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Authorized (protected) courses
CREATE TABLE IF NOT EXISTS authorized_courses (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS authorized_lectures (
  id TEXT PRIMARY KEY,
  course_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(course_id) REFERENCES authorized_courses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS authorized_media (
  id TEXT PRIMARY KEY,
  lecture_id TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('video','file')),
  url TEXT NOT NULL,
  original_name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(lecture_id) REFERENCES authorized_lectures(id) ON DELETE CASCADE
);

-- Notes Categories (hierarchical)
CREATE TABLE IF NOT EXISTS notes_categories (
  id TEXT PRIMARY KEY,
  parent_id TEXT REFERENCES notes_categories(id) ON DELETE CASCADE,
  name TEXT NOT NULL
);

-- Notes table (is_public = 1 => public, 0 => authorized)
CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  category_id TEXT REFERENCES notes_categories(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  description TEXT,
  is_public INTEGER NOT NULL DEFAULT 1,
  file_url TEXT NOT NULL,
  original_name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Attempt to extend authorized_media for role classification (ignore error if exists)
-- (Handled at runtime with ALTER)
