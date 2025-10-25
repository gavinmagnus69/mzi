import random
def is_prime(n, k=5):
    # Even numbers, except 2, are not prime
    if n % 2 == 0:
        return False
    
    # Represent n-1 as d * 2^r
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    
    # Run k rounds of the Miller-Rabin test
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def generate_q():
    while True:
        # Generate a random 256-bit number
        q = random.getrandbits(256)
        # Ensure the number falls within the required range (254 - 256 bits)
        q = q % (2 ** 256) + 2 ** 254
        if is_prime(q):
            return q

def generate_p(q):
    return 2 * q + 1

def generate_g(p, q):
    for g in range(1, p):
        if pow(g, q, p) == 1:
            return g
    return -1

