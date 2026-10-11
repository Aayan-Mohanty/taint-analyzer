# EXPECT: no warnings (the tainted value is replaced before the sink)
def report(cursor):
    q = input()
    q = "SELECT COUNT(*) FROM users"
    cursor.execute(q)
