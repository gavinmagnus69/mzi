import random
import gost
import hashlib

HASH_ALGO = gost.HASH_ALGO

def generate_signature(message, p, q, g, d):
    # Step 1 - Compute the message hash
    h = HASH_ALGO(message.encode('utf-8')).digest()
    
    # Step 2 - Convert the hash to the integer e
    a = int.from_bytes(h, byteorder='big')
    e = a % q
    if e == 0:
        e = 1
    
    while True:
        # Step 3 - Choose a random per-signature nonce k
        k = random.randint(1, q - 1)
        
        # Step 4 - Compute r = (g^k mod p) mod q
        r = pow(g, k, p) % q
        if r == 0:
            continue
        
        # Step 5 - Compute s = (r*d + k*e) mod q
        s = (r * d + k * e) % q
        if s == 0:
            continue
        
        return r, s, h

def verify_signature(message, p, q, g, Q, r, s):
    # Step 1 - Ensure r and s lie within 0 < value < q
    if not (0 < r < q and 0 < s < q):
        return False
    
    # Step 2 - Compute the message hash 
    h = HASH_ALGO(message.encode('utf-8')).digest()
    
    # Step 3 - Convert the hash to the integer e
    a = int.from_bytes(h, byteorder='big')
    e = a % q
    if e == 0:
        e = 1
    
    # Step 4 - Compute the modular inverse v = e^{-1} mod q
    v = pow(e, -1, q)
    
    # Step 5 - Compute z1 = s*v mod q and z2 = -r*v mod q
    z1 = (s * v) % q
    z2 = (-r * v) % q
    
    # Step 6 - Compute R = (g^z1 * Q^z2 mod p) mod q
    C = (pow(g, z1, p) * pow(Q, z2, p)) % p
    R = C % q
    
    # Step 7 - Verify R == r
    return R == r
