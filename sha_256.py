import struct
import hashlib

# SHA-256 operates on 32-bit words 
# Algorithm is defined with addition modulo 2^32, so every sum must be reduced to its lowest 32 bits
MASK = 0xFFFFFFFF

# Circular right shift, defined in Sec 2.2.2
# x is a 32-bit word and n is an integer from 0 to 32
def rotr(x, n):
    return ((x >> n) | (x << 32 - n)) & MASK

# Right shift, defined in Sec. 2.2.2
# x is a 32-bit word and n is an integer from 0 to 32
def shr(x, n):
    return (x >> n) & MASK

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

# Padded message must be a multiple of 512 bits
# Padding rule, defined in Sec. 5.1.1
# l + 1 + k = 448 mod 512
def pad(msg: bytes) -> bytes:
    bit_len = len(msg) * 8      # stores msg length in bits
    msg += b'\x80'              # adds 1 byte
    msg += b'\x00' * ((56 - len(msg)) % 64) # appends '0' bytes until length is 56 mod 64 (leaves 8 bytes for the length field)
                                            # if msg is already past byte 56, handled by mod 64 (pushes into next block)
    return msg + bit_len.to_bytes(8, 'big') # 
