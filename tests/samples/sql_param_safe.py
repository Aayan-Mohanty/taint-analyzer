# EXPECT: no warnings (parameterized query: the value is sent separately from the SQL text)
def find_user(cursor):
    name = input("Name: ")
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
