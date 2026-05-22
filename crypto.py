import random
import hashlib
import json
import os

# ==================== AES-128 (ECB, PKCS7) ====================

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a, b):
    """Multiply two bytes in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _key_expansion(key):
    """Expand 16-byte AES-128 key into 11 round keys (each 16 bytes)."""
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]               # RotWord
            temp = [_SBOX[b] for b in temp]          # SubWord
            temp[0] ^= _RCON[i // 4 - 1]             # XOR Rcon
        w.append([t ^ p for t, p in zip(temp, w[i - 4])])
    return [[b for word in w[r * 4:(r + 1) * 4] for b in word] for r in range(11)]


def _shift_rows(state):
    """ShiftRows on column-major flat 16-byte state."""
    s = list(state)
    s[1],  s[5],  s[9],  s[13] = state[5],  state[9],  state[13], state[1]
    s[2],  s[6],  s[10], s[14] = state[10], state[14], state[2],  state[6]
    s[3],  s[7],  s[11], s[15] = state[15], state[3],  state[7],  state[11]
    return s


def _inv_shift_rows(state):
    """Inverse ShiftRows."""
    s = list(state)
    s[1],  s[5],  s[9],  s[13] = state[13], state[1],  state[5],  state[9]
    s[2],  s[6],  s[10], s[14] = state[10], state[14], state[2],  state[6]
    s[3],  s[7],  s[11], s[15] = state[7],  state[11], state[15], state[3]
    return s


def _mix_columns(state):
    """MixColumns transformation."""
    result = list(state)
    for c in range(4):
        s0, s1, s2, s3 = state[c*4], state[c*4+1], state[c*4+2], state[c*4+3]
        result[c*4]   = _gmul(s0, 2) ^ _gmul(s1, 3) ^ s2         ^ s3
        result[c*4+1] = s0            ^ _gmul(s1, 2) ^ _gmul(s2, 3) ^ s3
        result[c*4+2] = s0            ^ s1            ^ _gmul(s2, 2) ^ _gmul(s3, 3)
        result[c*4+3] = _gmul(s0, 3) ^ s1            ^ s2            ^ _gmul(s3, 2)
    return result


def _inv_mix_columns(state):
    """Inverse MixColumns transformation."""
    result = list(state)
    for c in range(4):
        s0, s1, s2, s3 = state[c*4], state[c*4+1], state[c*4+2], state[c*4+3]
        result[c*4]   = _gmul(s0,14) ^ _gmul(s1,11) ^ _gmul(s2,13) ^ _gmul(s3, 9)
        result[c*4+1] = _gmul(s0, 9) ^ _gmul(s1,14) ^ _gmul(s2,11) ^ _gmul(s3,13)
        result[c*4+2] = _gmul(s0,13) ^ _gmul(s1, 9) ^ _gmul(s2,14) ^ _gmul(s3,11)
        result[c*4+3] = _gmul(s0,11) ^ _gmul(s1,13) ^ _gmul(s2, 9) ^ _gmul(s3,14)
    return result


def _encrypt_block(block, round_keys):
    state = list(block)
    state = [s ^ k for s, k in zip(state, round_keys[0])]
    for r in range(1, 10):
        state = [_SBOX[b] for b in state]
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = [s ^ k for s, k in zip(state, round_keys[r])]
    state = [_SBOX[b] for b in state]
    state = _shift_rows(state)
    state = [s ^ k for s, k in zip(state, round_keys[10])]
    return bytes(state)


def _decrypt_block(block, round_keys):
    state = list(block)
    state = [s ^ k for s, k in zip(state, round_keys[10])]
    for r in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = [_INV_SBOX[b] for b in state]
        state = [s ^ k for s, k in zip(state, round_keys[r])]
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = [_INV_SBOX[b] for b in state]
    state = [s ^ k for s, k in zip(state, round_keys[0])]
    return bytes(state)


def aes_encrypt(plaintext, key):
    """Encrypt string/bytes with AES-128 ECB + PKCS7 padding. Returns bytes."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    pad = 16 - len(plaintext) % 16
    plaintext += bytes([pad]) * pad
    rk = _key_expansion(key)
    result = b''
    for i in range(0, len(plaintext), 16):
        result += _encrypt_block(plaintext[i:i + 16], rk)
    return result


def aes_decrypt(ciphertext, key):
    """Decrypt AES-128 ECB ciphertext (bytes). Returns plaintext string."""
    rk = _key_expansion(key)
    result = b''
    for i in range(0, len(ciphertext), 16):
        result += _decrypt_block(ciphertext[i:i + 16], rk)
    pad = result[-1]
    return result[:-pad].decode('utf-8')


# ==================== RSA ====================

def _is_prime(n, k=20):
    """Miller-Rabin primality test."""
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    """Generate a random prime of exactly `bits` bits."""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1   # set high bit and make odd
        if _is_prime(n):
            return n


def _mod_inv(a, m):
    """Modular inverse via extended Euclidean algorithm."""
    g, x, u = m, 0, 1
    a0 = a
    while a0 != 0:
        q = g // a0
        g, a0 = a0, g - q * a0
        x, u = u, x - q * u
    return x % m


def rsa_generate_keys(bits=512):
    """Generate RSA key pair. Returns ((n,e), (n,d))."""
    p = _gen_prime(bits // 2)
    q = _gen_prime(bits // 2)
    while q == p:
        q = _gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = _mod_inv(e, phi)
    return (n, e), (n, d)


def rsa_encrypt(data_bytes, public_key):
    """Encrypt bytes with RSA public key (textbook RSA). Returns bytes."""
    n, e = public_key
    m = int.from_bytes(data_bytes, 'big')
    c = pow(m, e, n)
    key_len = (n.bit_length() + 7) // 8
    return c.to_bytes(key_len, 'big')


def rsa_decrypt(ciphertext_bytes, private_key, msg_len=16):
    """Decrypt RSA ciphertext. Returns `msg_len` bytes."""
    n, d = private_key
    c = int.from_bytes(ciphertext_bytes, 'big')
    m = pow(c, d, n)
    return m.to_bytes(msg_len, 'big')


RSA_PUBLIC_FILE  = "rsa_public.json"
RSA_PRIVATE_FILE = "rsa_private.json"


def rsa_keys_exist():
    return os.path.exists(RSA_PUBLIC_FILE) and os.path.exists(RSA_PRIVATE_FILE)


def save_rsa_keys(public_key, private_key):
    with open(RSA_PUBLIC_FILE, 'w') as f:
        json.dump({'n': public_key[0], 'e': public_key[1]}, f)
    with open(RSA_PRIVATE_FILE, 'w') as f:
        json.dump({'n': private_key[0], 'd': private_key[1]}, f)


def load_rsa_keys():
    with open(RSA_PUBLIC_FILE) as f:
        pub = json.load(f)
    with open(RSA_PRIVATE_FILE) as f:
        priv = json.load(f)
    return (pub['n'], pub['e']), (priv['n'], priv['d'])


# ==================== Diffie-Hellman ====================

# RFC 3526 1024-bit MODP Group (safe prime, well-known)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)
DH_G = 2


def dh_generate_private():
    """Generate a random DH private key."""
    return random.randint(2, DH_P - 2)


def dh_compute_public(private):
    """Compute g^private mod p."""
    return pow(DH_G, private, DH_P)


def dh_compute_shared(other_public, my_private):
    """Compute shared secret: other_public^my_private mod p."""
    return pow(other_public, my_private, DH_P)


def dh_derive_aes_key(shared_secret):
    """Derive a 16-byte AES key from the DH shared secret using SHA-256."""
    return hashlib.sha256(str(shared_secret).encode()).digest()[:16]
