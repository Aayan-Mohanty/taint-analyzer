# EXPECT: no warnings (int() can only produce a number)
def get_order(cursor):
    order_id = int(input("Order id: "))
    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")
