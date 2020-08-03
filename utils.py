import bcrypt
from math import log2


def hash_password(username, password):
    rounds = sum([ord(x) for x in username])
    rounds  = int(log2(rounds))
    password = password.encode('utf-8')
    
    bits = bcrypt.hashpw(password, salt=bcrypt.gensalt(rounds))
    return bits.decode('utf-8')


def check_password(passwd, hashed_passwd):
    return bcrypt.checkpw(passwd.encode('utf-8'), hashed_passwd.encode('utf-8'))
