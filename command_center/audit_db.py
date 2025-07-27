import sqlite3
import os
import hashlib
from datetime import datetime

def init_audit_db():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit.db")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            source TEXT NOT NULL,
            user_id INTEGER,
            log_hash TEXT NOT NULL UNIQUE,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS log_rotation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rotation_time TEXT NOT NULL,
            logs_archived INTEGER
        )
    ''')
    
    conn.commit()
    conn.close()
    return db_path

if __name__ == '__main__':
    init_audit_db()