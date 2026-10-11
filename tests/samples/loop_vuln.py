# EXPECT: sql_injection at line 6 (tainted on the second loop iteration)
# NOTE: missed by the linear analyzer, which reads the loop body only once.
def poll(cursor):
    q = "SELECT 1"
    for _ in range(3):
        cursor.execute(q)
        q = input()
