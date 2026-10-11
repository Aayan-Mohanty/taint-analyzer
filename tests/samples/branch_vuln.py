# EXPECT: sql_injection at line 9
# NOTE: missed by the preliminary linear analyzer (Step 5), because it treats
# the else-branch as running after the if-branch. Detected after Step 7.
def search(cursor, ask_user):
    if ask_user:
        term = input()
    else:
        term = "all"
    cursor.execute("SELECT * FROM items WHERE tag = '" + term + "'")
