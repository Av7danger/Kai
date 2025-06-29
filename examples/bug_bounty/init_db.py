#!/usr/bin/env python3
"""
Database Initialization Script
"""

import sqlite3

def init_database():
    conn = sqlite3.connect('bb_pro.db')
    cursor = conn.cursor()

    # Create tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        scope TEXT,
        status TEXT DEFAULT 'active',
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        title TEXT NOT NULL,
        vuln_type TEXT,
        severity TEXT,
        description TEXT,
        location TEXT,
        technical_details TEXT,
        status TEXT DEFAULT 'open',
        found_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (target_id) REFERENCES targets (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        file_type TEXT,
        content TEXT,
        extracted_targets TEXT,
        uploaded_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Insert sample data
    sample_targets = [
        (1, "Example Target", "https://example.com", "*.example.com"),
        (2, "Test Application", "https://testapp.local", "testapp.local"),
        (3, "Demo Site", "https://demo.example.org", "demo.example.org")
    ]
    
    for target in sample_targets:
        cursor.execute('INSERT OR IGNORE INTO targets (id, name, url, scope) VALUES (?, ?, ?, ?)', target)

    sample_vulns = [
        (1, 1, "Reflected XSS in search parameter", "XSS", "High", "User input is reflected without proper sanitization", "/search?q="),
        (2, 1, "SQL Injection in login form", "SQL Injection", "Critical", "SQL injection vulnerability in username field", "/login"),
        (3, 2, "IDOR in user profile", "IDOR", "Medium", "Direct object reference allows access to other users", "/profile?id="),
        (4, 2, "CSRF in password change", "CSRF", "Medium", "Password change lacks CSRF protection", "/change-password"),
        (5, 3, "Local File Inclusion", "LFI", "High", "File parameter allows directory traversal", "/download?file=")
    ]
    
    for vuln in sample_vulns:
        cursor.execute('INSERT OR IGNORE INTO vulnerabilities (id, target_id, title, vuln_type, severity, description, location) VALUES (?, ?, ?, ?, ?, ?, ?)', vuln)

    conn.commit()
    conn.close()
    print("✅ Database initialized with sample data")
    print("📊 Added 3 targets and 5 vulnerabilities")

if __name__ == "__main__":
    init_database()
