# EXPECT: code_injection at line 5 (the sink is inside an if-condition)
def check():
    rule = input()
    while True:
        if eval(rule):
            break
