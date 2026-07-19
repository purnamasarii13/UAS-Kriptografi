"""
Simplified DES (S-DES) - manual implementation (Stallings' scheme).
10-bit key, 8-bit plaintext/ciphertext blocks. Every stage is recorded.
"""

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

S0 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 3, 2]]

S1 = [[0, 1, 2, 3],
      [2, 0, 1, 3],
      [3, 0, 1, 0],
      [2, 1, 0, 3]]


def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)


def left_shift(bits, n):
    return bits[n:] + bits[:n]


def xor(a, b):
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))


def validate_bits(s, length):
    return len(s) == length and all(c in '01' for c in s)


def generate_keys(key10):
    p10 = permute(key10, P10)
    left, right = p10[:5], p10[5:]
    ls1_l, ls1_r = left_shift(left, 1), left_shift(right, 1)
    k1 = permute(ls1_l + ls1_r, P8)
    ls2_l, ls2_r = left_shift(ls1_l, 2), left_shift(ls1_r, 2)
    k2 = permute(ls2_l + ls2_r, P8)
    steps = {
        'key10': key10, 'p10': p10, 'left0': left, 'right0': right,
        'ls1_left': ls1_l, 'ls1_right': ls1_r, 'k1': k1,
        'ls2_left': ls2_l, 'ls2_right': ls2_r, 'k2': k2
    }
    return k1, k2, steps


def sbox_lookup(sbox, bits4, name):
    row = int(bits4[0] + bits4[3], 2)
    col = int(bits4[1] + bits4[2], 2)
    val = sbox[row][col]
    out2 = bin(val)[2:].zfill(2)
    return out2, {'box': name, 'input': bits4, 'row': row, 'col': col, 'value': val, 'output': out2}


def fk(bits8, subkey, round_no):
    left, right = bits8[:4], bits8[4:]
    ep = permute(right, EP)
    xored = xor(ep, subkey)
    left4, right4 = xored[:4], xored[4:]
    s0_out, s0_detail = sbox_lookup(S0, left4, 'S0')
    s1_out, s1_detail = sbox_lookup(S1, right4, 'S1')
    p4_in = s0_out + s1_out
    p4_out = permute(p4_in, P4)
    new_left = xor(left, p4_out)
    detail = {
        'round': round_no, 'left_in': left, 'right_in': right,
        'expansion': ep, 'subkey': subkey, 'xor_result': xored,
        's0': s0_detail, 's1': s1_detail, 'p4_input': p4_in, 'p4_output': p4_out,
        'xor_left': new_left, 'unchanged_right': right,
        'output': new_left + right
    }
    return new_left + right, detail


def run(input8, key10, mode):
    """mode: 'encrypt' or 'decrypt'. input8 is plaintext (encrypt) or ciphertext (decrypt)."""
    k1, k2, key_steps = generate_keys(key10)
    if mode == 'decrypt':
        first_key, second_key = k2, k1
    else:
        first_key, second_key = k1, k2

    ip_out = permute(input8, IP)
    fk1_out, fk1_detail = fk(ip_out, first_key, 1)
    swapped = fk1_out[4:] + fk1_out[:4]
    fk2_out, fk2_detail = fk(swapped, second_key, 2)
    final = permute(fk2_out, IP_INV)

    process = {
        'input': input8, 'mode': mode, 'key_schedule': key_steps,
        'k1_used_round1': first_key, 'k2_used_round2': second_key,
        'initial_permutation': ip_out,
        'round1': fk1_detail,
        'swap': swapped,
        'round2': fk2_detail,
        'inverse_ip': final
    }
    return final, process


def encrypt(plaintext8, key10):
    out_bin, process = run(plaintext8, key10, 'encrypt')
    out_hex = hex(int(out_bin, 2))[2:].upper().zfill(2)
    return out_hex, out_bin, process


def decrypt(ciphertext8, key10):
    out_bin, process = run(ciphertext8, key10, 'decrypt')
    out_hex = hex(int(out_bin, 2))[2:].upper().zfill(2)
    return out_hex, out_bin, process
