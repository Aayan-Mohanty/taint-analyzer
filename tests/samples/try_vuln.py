# EXPECT: sql_injection at line 9
# If int(v) raises ValueError, v still holds the raw input inside the handler.
# NOTE: missed by the linear analyzer, which gives the handler only the state at the end of the try body.
def load(cursor):
    try:
        v = input()
        v = int(v)
    except ValueError:
        cursor.execute("SELECT * FROM t WHERE k = '" + v + "'")
