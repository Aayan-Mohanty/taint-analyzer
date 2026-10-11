# EXPECT (truth): no real vulnerability. The tainted path needs flag to be both
# true and false, which is impossible.
# EXPECT (tool): sql_injection at line 10 = FALSE POSITIVE. The analysis is
# path-insensitive: it does not track that both conditions test the same flag.
def report(cursor, flag):
    q = "SELECT 1"
    if flag:
        q = input()
    if not flag:
        cursor.execute(q)
