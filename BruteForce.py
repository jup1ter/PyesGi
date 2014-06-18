import random
import hashlib
import time
import sql

def sha1(pwd):
    pwd = pwd.encode('utf-8')
    m = hashlib.sha1()
    m.update(pwd)
    return(m.hexdigest())

def pwd(p):
    string = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    pw_length = p
    key = ""

    for i in range(pw_length):
        next_index = random.randrange(len(string))
        key = key + string[next_index]
    return(key)


nb = int(input("\nNumber of characters : "))
file = open("accounts2.txt", "r")
tps1 = time.clock()
print("\nworking...")
for line in file:
    dico = line.split(',' or '\n')
    found = ""
    i = 0
    while dico[1] != found:
        keys = pwd(nb)
        found = sha1(keys+dico[2])
        i += 1

    tps2 = time.strftime('%H:%M:%S', time.clock()-tps1)

    
