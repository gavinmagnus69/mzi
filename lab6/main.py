import random
from primes import generate_q, generate_p, generate_g
from signature import generate_signature, verify_signature

def main():
    message_original = "This is correct message"
    message_incorrect = "This is incorrect message"
    print(f"Base message: {message_original}")
    print(f"Base  incorrect message: {message_incorrect}")
    print("Params:")
    q = generate_q()
    p = generate_p(q)
    g = generate_g(p, q)
    
    d = random.randint(1, q - 1)  # Private key
    Q = pow(g, d, p)  # Public key
    print(f"\n q={q},\n p={p},\n d={d}")
    r, s, _ = generate_signature(message_original, p, q, g, d) 
    # print(f"Signature parameters:\n r={r},\n s={s}\n")
    signature = f"{r:X}{s:X}"
    # print(f"Hash (original message): {''.join(f'{x:02x}' for x in text_hash)}")
    print(f"Signature: {signature}")
    is_valid_correct = verify_signature(message_original, p, q, g, Q, r, s)
    print(f"Signature valid (correct message): {is_valid_correct}")

    r, s, _ = generate_signature(message_incorrect, p, q, g, d) 
    is_valid_correct = verify_signature(message_original, p, q, g, Q, r+1 , s)
    print(f"Signature valid (incorrect message): {is_valid_correct}")



if __name__ == "__main__":
    main()
