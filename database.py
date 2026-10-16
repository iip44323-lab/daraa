# -*- coding: utf-8 -*-
import sqlite3
import hashlib
from datetime import datetime, timedelta
import config


def init_db():
    conn = sqlite3.connect(config.DB_FILE)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password_hash TEXT, company TEXT, phone TEXT, plan TEXT DEFAULT \'free\', trial_ends TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
    c.execute('CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, target_url TEXT, scan_type TEXT, status TEXT DEFAULT \'pending\', score INTEGER, result TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
    conn.commit()
    conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def create_user(email, password, company, phone):
    conn = sqlite3.connect(config.DB_FILE)
    c = conn.cursor()
    trial_ends = datetime.now() + timedelta(days=7)
    try:
        c.execute('INSERT INTO users (email, password_hash, company, phone, trial_ends) VALUES (?,?,?,?,?)', (email, hash_password(password), company, phone, trial_ends))
        user_id = c.lastrowid
        conn.commit()
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def login_user(email, password):
    conn = sqlite3.connect(config.DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, email, company, plan, trial_ends FROM users WHERE email = ? AND password_hash = ?', (email, hash_password(password)))
    user = c.fetchone()
    conn.close()
    return user


def save_scan(user_id, target_url, scan_type, score, result):
    conn = sqlite3.connect(config.DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO scans (user_id, target_url, scan_type, status, score, result) VALUES (?,?,?,?,?,?)', (user_id, target_url, scan_type, 'completed', score, str(result)))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_user_scans(user_id):
    conn = sqlite3.connect(config.DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, target_url, score, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', (user_id,))
    rows = c.fetchall()
    conn.close()
    return rows


init_db()