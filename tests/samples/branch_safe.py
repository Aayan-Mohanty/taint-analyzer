# EXPECT: no warnings (x is made safe on every path before the sink)
def lookup(cursor, flag):
    x = input()
    if flag:
        x = int(x)
    else:
        x = 0
    cursor.execute(f"SELECT * FROM t WHERE id = {x}")
