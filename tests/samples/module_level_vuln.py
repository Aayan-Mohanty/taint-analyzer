# EXPECT: sql_injection at line 7 (top-level script code is analyzed too)
import sqlite3

conn = sqlite3.connect("app.db")
cursor = conn.cursor()
user = input()
cursor.execute("DELETE FROM sessions WHERE user = '%s'" % user)
