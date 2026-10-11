# EXPECT: sql_injection at line 7
import sqlite3

def find_user(cursor):
    name = input("Name: ")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
