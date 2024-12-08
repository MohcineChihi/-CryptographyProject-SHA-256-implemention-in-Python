# -*- coding: utf-8 -*-
"""
Created on Sun Dec  1 14:00:15 2024

@author: mohcine
"""

# SHA-256 constants
SHA256_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def rotate_right(value: int, shift: int, bits: int = 32) -> int:
    return ((value >> shift) | (value << (bits - shift))) & 0xffffffff

    #SHA256 choose
def sha256_ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)

    #SHA256 majority
def sha256_maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)

def sha256_bigsigma0(w: int) -> int:
    #BigSigma0 : ROTR 2, 13, 22
    return (rotate_right(w, 2) ^ rotate_right(w, 13) ^ rotate_right(w, 22))

def sha256_bigsigma1(w: int) -> int:
    #BigSigma1 : ROTR 6, 11, 25
    return (rotate_right(w, 6) ^ rotate_right(w, 11) ^ rotate_right(w, 25))

def sha256_smallsigma0(w: int) -> int:
    #SmallSigma0 : ROTR 7, 18 and SHR 3
    return (rotate_right(w, 7) ^ rotate_right(w, 18) ^ (w >> 3))

def sha256_smallsigma1(w: int) -> int:
    #SmallSigma1 : ROTR 17, 19 and SHR 10
    return (rotate_right(w, 17) ^ rotate_right(w, 19) ^ (w >> 10))

def pad_message(data) -> bytearray:
    """Perform SHA-256 padding on the input message."""
    if isinstance(data, str):
        data = bytearray(data, 'ascii')
    elif isinstance(data, bytes):
        data = bytearray(data)
    elif not isinstance(data, bytearray):
        raise TypeError("Expected str, bytes or bytearray")

    original_len = len(data) * 8
    #Append 0x80 (10000000 in binary)
    data.append(0x80)
    #Append 0x00 until the length (in bits) modulo 512 is 448
    while (len(data)*8 + 64) % 512 != 0:
        data.append(0x00)
    #Append the original length as a 64 bit big endian integer
    data += original_len.to_bytes(8, 'big')
    return data

def prepare_schedule(chunk: bytes) -> list:
    """Prepare the message schedule (64 words) for the given 512-bit chunk."""
    w = []
    #First 16 words come directly from the chunk
    for i in range(16):
        w.append(int.from_bytes(chunk[i*4:(i*4)+4], 'big'))
    #Remaining words are generated using the small sigma functions
    for i in range(16, 64):
        s0 = sha256_smallsigma0(w[i-15])
        s1 = sha256_smallsigma1(w[i-2])
        w.append((w[i-16] + w[i-7] + s0 + s1) & 0xffffffff)
    return w

def process_block(block: bytes, h: list) -> None:
    """Process a 512-bit block and update the hash values in h."""
    w = prepare_schedule(block)
    a, b, c, d, e, f, g, hh = h

    #Main loop : 64 rounds
    for i in range(64):
        t1 = (hh + sha256_bigsigma1(e) + sha256_ch(e, f, g) + SHA256_CONSTANTS[i] + w[i]) & 0xffffffff
        t2 = (sha256_bigsigma0(a) + sha256_maj(a, b, c)) & 0xffffffff
        hh = g
        g = f
        f = e
        e = (d + t1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xffffffff

    #Update the hash values
    h[0] = (h[0] + a) & 0xffffffff
    h[1] = (h[1] + b) & 0xffffffff
    h[2] = (h[2] + c) & 0xffffffff
    h[3] = (h[3] + d) & 0xffffffff
    h[4] = (h[4] + e) & 0xffffffff
    h[5] = (h[5] + f) & 0xffffffff
    h[6] = (h[6] + g) & 0xffffffff
    h[7] = (h[7] + hh) & 0xffffffff

def sha256_modified(message) -> bytes:
    """Compute the SHA-256 hash for the given message."""
    #Initial hash values (IV)
    h_values = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    #Pad the message
    padded = pad_message(message)

    #Process each 512-bit block
    for offset in range(0, len(padded), 64):
        block = padded[offset:offset+64]
        process_block(block, h_values)

    #Produce the final 256 bit (32 byte) hash
    result = b''.join(h.to_bytes(4, 'big') for h in h_values)
    return result

if __name__ == "__main__":
    #Asking for input
    user_input = input("Enter a message : ")
    hash_value = sha256_modified(user_input)
    print("SHA-256:", hash_value.hex())