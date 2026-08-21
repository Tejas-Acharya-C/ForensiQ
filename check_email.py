import sqlite3
conn = sqlite3.connect('forensiq.db')
rows = conn.execute("SELECT email, is_active FROM users").fetchall()
for r in rows:
    print(repr(r[0]), "active:", r[1])
conn.close()
