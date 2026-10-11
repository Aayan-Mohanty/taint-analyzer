# EXPECT: sql_injection at line 9
# NOTE: missed by the linear analyzer (--linear), because it treats
# the else-branch as running after the if-branch. The CFG analysis detects it.
def search(cursor, ask_user):
    if ask_user:
        term = input()
    else:
        term = "all"
    cursor.execute("SELECT * FROM items WHERE tag = '" + term + "'")
