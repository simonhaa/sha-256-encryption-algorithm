import struct
import hashlib

# SHA-256 operates on 32-bit words 
# Algorithm is defined with addition modulo 2^32, so every sum must be reduced to its lowest 32 bits
MASK = 0xFFFFFFFF

# Circular right shift, defined in Sec 2.2.2
# x is a 32-bit word and n is an integer from 0 to 32
def rotr(x, n):
    return ((x >> n) | (x << 32 - n)) & MASK

def Ch(x, y, z):
    return ((x & y) ^ (~x & z)) & MASK

def Maj(x, y, z):
    return ((x & y) ^ (y & z) ^ (x & z)) & MASK

# Generates a list of primes equal to the number n
def first_primes(n):
    primes, c = [], 2
    while len(primes) < n:
        # c% p = remainder of c dividing by p
        # non-zero for when c does not divide by p
        # all is true if every earlier prime leaves a remainder
        if all(c % p for p in primes):
            # Adds c if its is prime, moves on to the next candidate, and returns list when done
            primes.append(c)
        c += 1
    return primes

# First 64 primes
PRIMES = first_primes(64)

# First 32 bits of the fractional parts of the square root of the first 8 prime numbers
# % 1 keeps only the fractional part (7.25 % 1 = 0.25)
# Multiplying by 2**32 shifts everything 32 places to the left
H_INIT = [int((p ** 0.5 % 1) * 2**32) for p in PRIMES[:8]]

# First 64 bits of the fractional parts of the cube root of the first 64 prime numbers
K = [int((p ** (1/3) % 1) * 2**32) for p in PRIMES]

# Padded message must be a multiple of 512 bits (total of 64 bytes)
# Padding rule, defined in Sec. 5.1.1
# l + 1 + k = 448 mod 512
def pad(msg: bytes) -> bytes:
    bit_len = len(msg) * 8      # stores msg length in bits
    msg += b'\x80'              # adds 1 byte
    msg += b'\x00' * ((56 - len(msg)) % 64) # appends '0' bytes until length is 56 (mod 64 because there needs to be 8 bytes for the length field)
    return msg + bit_len.to_bytes(8, 'big') # 64-bit block equal to the number l (original length of msg)

def sha256(msg: bytes) -> bytes:
    H = H_INIT[:] # copy of H_INIT
    data = pad(msg) # pads the message
    # off takes the values 0, 64, 128, ...
    for off in range(0, len(data), 64): # loop over the message blocks
        # Message Schedule
        # Slice out the current block, unpack into 16 big-endian 32-bit words (tuple)
        # Convert to a list that we can append (w[0] - w[15])
        w = list(struct.unpack('>16I', data[off:off+64])) # big-endian, repeat 16 times, unsigned 32-bit integer
        for i in range(16, 64):
            s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)  # Sec 4.1.2 functions (7)
            s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)   # Sec 4.1.2 functions (8)
            w.append((w[i-16] + s0 + w[i-7] + s1) & MASK)

        # Compression
        a, b, c, d, e, f, g, h = H # eight working variables
        for i in range(64): # 64 rounds, one per schedule word
            ch = (e & f) ^ (~e & g)                         # Section 4.1.2 functions (3)
            maj = (a & b) ^ (a & c) ^ (b & c)               # Section 4.1.2 functions (4)
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)     # Section 4.1.2 functions (5)
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)     # Section 4.1.2 functions (6)
            t1 = (h + S1 + ch + K[i] + w[i]) & MASK         # temp words
            t2 = (S0 + maj) & MASK                          # temp words
            h, g, f = g, f, e
            e = (d + t1) & MASK
            d, c, b = c, b, a
            a = (t1 + t2) & MASK
            # Use to check against simulation waveform
            print(i, [f"{v:08x}" for v in (a, b, c, d, e, f, g, h)])

        # After 64 rounds, adds the working variables back into the old hash state
        # zip pairs up x (old H[j]) and y (matching working variable)
        H = [(x + y) & MASK for x, y in zip(H, (a, b, c, d, e, f, g, h))]

    # Converts each of the 8 words into 4 big-endian bytes and concatenates them, giving the 256-bit digest
    return b''.join(x.to_bytes(4, 'big') for x in H)

# Verify against the standard library
for m in [b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, b"a" * 1000]:
    assert sha256(m) == hashlib.sha256(m).digest(), m
print(sha256(b"abc").hex())