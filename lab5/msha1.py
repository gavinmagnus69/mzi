import struct


class SHA1:
    @staticmethod
    def hash(message_bytes):
        # Initialize the SHA-1 state constants
        A = 0x67452301
        B = 0xEFCDAB89
        C = 0x98BADCFE
        D = 0x10325476
        E = 0xC3D2E1F0

        # Prepare the padded message as a bytearray
        bytes_ = bytearray(message_bytes)
        bytes_.append(0x80)  # Append the single 1 bit that starts the padding

        # Pad with zeros until the length is congruent to 56 bytes (448 bits)
        while len(bytes_) % 64 != 56:
            bytes_.append(0x00)

        # Append the original message length (in bits) to the end of the message
        message_length_bits = len(message_bytes) * 8  # Convert length in bytes to bits
        bytes_.extend(struct.pack('>Q', message_length_bits))  # Store length as big-endian for cross-platform consistency

        # Process the message in 512-bit (64 byte) chunks
        for i in range(0, len(bytes_), 64):
            # Create an array of 80 32-bit words
            w = [0] * 80

            # Load the current block into the first 16 words
            for j in range(16):
                w[j] = struct.unpack('>I', bytes_[i + j * 4:i + j * 4 + 4])[0]

            # Extend the schedule to 80 words
            for j in range(16, 80):
                w[j] = SHA1.rotate_left(w[j - 16] ^ w[j - 14] ^ w[j - 8] ^ w[j - 3], 1)

            # Initialize working variables for this block
            a, b, c, d, e = A, B, C, D, E

            # Main compression loop
            for j in range(80):
                if j < 20:
                    f = (b & c) | (~b & d)
                    k = 0x5A827999
                elif j < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif j < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = (SHA1.rotate_left(a, 5) + f + e + k + w[j]) & 0xFFFFFFFF
                a, b, c, d, e = temp, a, SHA1.rotate_left(b, 30), c, d

            # Add the results back into the running hash state modulo 2^32
            A = (A + a) & 0xFFFFFFFF
            B = (B + b) & 0xFFFFFFFF
            C = (C + c) & 0xFFFFFFFF
            D = (D + d) & 0xFFFFFFFF
            E = (E + e) & 0xFFFFFFFF

        # Concatenate h0 through h4 into the final hash value
        hash_bytes = struct.pack('>5I', A, B, C, D, E)
        return hash_bytes

    # Method for performing a cyclic left rotation
    @staticmethod
    def rotate_left(value, bits):
        return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF
