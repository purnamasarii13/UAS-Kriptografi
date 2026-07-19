"""
Simplified AES (S-AES) - manual implementation (Musa/Schaefer/Wedig scheme).
16-bit key, 16-bit plaintext/ciphertext blocks (2x2 nibble state), 2 rounds.
"""

SBOX = {
 '0000': '1001', '0001': '0100', '0010': '1010', '0011': '1011',
 '0100': '1101', '0101': '0001', '0110': '1000', '0111': '0101',
 '1000': '0110', '1001': '0010', '1010': '0000', '1011': '0011',
 '1100': '1100', '1101': '1110', '1110': '1111', '1111': '0111'
}
INV_SBOX = {v: k for k, v in SBOX.items()}

RCON1 = '10000000'
RCON2 = '00110000'

# GF(2^4) multiplication with irreducible poly x^4+x+1 (0b10011)
def gmul4(a, b):
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        hi = a & 0x8
        a = (a << 1) & 0xF
        if hi:
            a ^= 0x3  # x^4 = x+1 -> reduce with 0b10011 & 0xF trick
        b >>= 1
    return p & 0xF


def nib_to_bin(n):
    return format(n, '04b')


def bin_to_nib(b):
    return int(b, 2)


def sub_nib(bits4):
    return SBOX[bits4]


def inv_sub_nib(bits4):
    return INV_SBOX[bits4]


def rot_nib(byte8):
    """swap the two nibbles of an 8-bit word"""
    return byte8[4:] + byte8[:4]


def xor(a, b):
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))


def sub_word(byte8):
    return sub_nib(byte8[:4]) + sub_nib(byte8[4:])


# ---------------------------- Key Expansion --------------------------------

def key_expansion(key16):
    w0, w1 = key16[:8], key16[8:]
    steps = {'w0': w0, 'w1': w1}

    rot = rot_nib(w1)
    sub = sub_word(rot)
    w2 = xor(xor(w0, sub), RCON1)
    w3 = xor(w2, w1)
    steps.update({'rotnib_w1': rot, 'subnib': sub, 'rcon1': RCON1, 'w2': w2, 'w3': w3})

    rot2 = rot_nib(w3)
    sub2 = sub_word(rot2)
    w4 = xor(xor(w2, sub2), RCON2)
    w5 = xor(w4, w3)
    steps.update({'rotnib_w3': rot2, 'subnib2': sub2, 'rcon2': RCON2, 'w4': w4, 'w5': w5})

    K0 = w0 + w1
    K1 = w2 + w3
    K2 = w4 + w5
    steps.update({'K0': K0, 'K1': K1, 'K2': K2})
    return K0, K1, K2, steps


# ---------------------------- State helpers ---------------------------------

def bits_to_state(bits16):
    """S-AES state: nibbles n0 n1 n2 n3 (bits[0:4],[4:8],[8:12],[12:16])
    arranged column-major as [[n0,n2],[n1,n3]]"""
    n0, n1, n2, n3 = bits16[0:4], bits16[4:8], bits16[8:12], bits16[12:16]
    return [[n0, n2], [n1, n3]]


def state_to_bits(state):
    n0, n2 = state[0]
    n1, n3 = state[1]
    return n0 + n1 + n2 + n3


def state_hex(state):
    return [[format(bin_to_nib(x), 'X') for x in row] for row in state]


def snapshot(state):
    return {'bin': [row[:] for row in state], 'hex': state_hex(state)}


def add_round_key(state, key16):
    kstate = bits_to_state(key16)
    return [[xor(state[r][c], kstate[r][c]) for c in range(2)] for r in range(2)]


def nibble_sub(state, inverse=False):
    f = inv_sub_nib if inverse else sub_nib
    return [[f(state[r][c]) for c in range(2)] for r in range(2)]


def shift_rows(state):
    """swap row 1 (second row)"""
    return [[state[0][0], state[0][1]], [state[1][1], state[1][0]]]


def mix_columns(state, inverse=False):
    m = [[1, 4], [4, 1]] if not inverse else [[9, 2], [2, 9]]
    new_state = [[0, 0], [0, 0]]
    for c in range(2):
        n0 = bin_to_nib(state[0][c])
        n1 = bin_to_nib(state[1][c])
        r0 = gmul4(m[0][0], n0) ^ gmul4(m[0][1], n1)
        r1 = gmul4(m[1][0], n0) ^ gmul4(m[1][1], n1)
        new_state[0][c] = nib_to_bin(r0)
        new_state[1][c] = nib_to_bin(r1)
    return new_state


# ---------------------------- Full Encrypt / Decrypt -------------------------

def run(input16, key16, mode):
    K0, K1, K2, key_steps = key_expansion(key16)
    state = bits_to_state(input16)
    process = {'input': input16, 'mode': mode, 'key_schedule': key_steps,
               'K0': K0, 'K1': K1, 'K2': K2}

    if mode == 'encrypt':
        process['initial_state'] = snapshot(state)
        state = add_round_key(state, K0)
        process['initial_add_round_key'] = snapshot(state)

        r1 = {'round': 1, 'input': snapshot(state)}
        state = nibble_sub(state)
        r1['sub_nib'] = snapshot(state)
        state = shift_rows(state)
        r1['shift_rows'] = snapshot(state)
        state = mix_columns(state)
        r1['mix_columns'] = snapshot(state)
        state = add_round_key(state, K1)
        r1['add_round_key'] = snapshot(state)
        process['round1'] = r1

        r2 = {'round': 2, 'input': snapshot(state)}
        state = nibble_sub(state)
        r2['sub_nib'] = snapshot(state)
        state = shift_rows(state)
        r2['shift_rows'] = snapshot(state)
        state = add_round_key(state, K2)
        r2['add_round_key'] = snapshot(state)
        process['round2'] = r2
    else:
        process['initial_state'] = snapshot(state)
        state = add_round_key(state, K2)
        process['initial_add_round_key'] = snapshot(state)

        r1 = {'round': 1, 'input': snapshot(state)}
        state = shift_rows(state)
        r1['inv_shift_rows'] = snapshot(state)
        state = nibble_sub(state, inverse=True)
        r1['inv_sub_nib'] = snapshot(state)
        state = add_round_key(state, K1)
        r1['add_round_key'] = snapshot(state)
        state = mix_columns(state, inverse=True)
        r1['inv_mix_columns'] = snapshot(state)
        process['round1'] = r1

        r2 = {'round': 2, 'input': snapshot(state)}
        state = shift_rows(state)
        r2['inv_shift_rows'] = snapshot(state)
        state = nibble_sub(state, inverse=True)
        r2['inv_sub_nib'] = snapshot(state)
        state = add_round_key(state, K0)
        r2['add_round_key'] = snapshot(state)
        process['round2'] = r2

    out_bits = state_to_bits(state)
    process['output_state'] = snapshot(state)
    return out_bits, process


def encrypt(plaintext16, key16):
    out_bin, process = run(plaintext16, key16, 'encrypt')
    out_hex = hex(int(out_bin, 2))[2:].upper().zfill(4)
    return out_hex, out_bin, process


def decrypt(ciphertext16, key16):
    out_bin, process = run(ciphertext16, key16, 'decrypt')
    out_hex = hex(int(out_bin, 2))[2:].upper().zfill(4)
    return out_hex, out_bin, process
