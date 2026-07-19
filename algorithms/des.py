"""
DES (Data Encryption Standard) - Full manual implementation.
Every stage of the algorithm is computed by hand (no crypto libraries)
and every intermediate value is recorded so the frontend can render
the complete process (PC-1, PC-2, key schedule, 16 Feistel rounds,
expansion, XOR, S-Box substitution, P-Box permutation, swaps, IP, FP).
"""

# ---------------------------------------------------------------------------
# Standard DES tables (FIPS 46-3)
# ---------------------------------------------------------------------------
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

SBOX = [
 # S1
 [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
  [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
  [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
  [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
 # S2
 [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
  [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
  [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
  [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
 # S3
 [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
  [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
  [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
  [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
 # S4
 [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
  [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
  [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
  [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
 # S5
 [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
  [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
  [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
  [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
 # S6
 [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
  [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
  [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
  [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
 # S7
 [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
  [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
  [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
  [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
 # S8
 [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
  [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
  [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
  [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]


def hex_to_bin(h, bits):
    return bin(int(h, 16))[2:].zfill(bits)


def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)


def xor(a, b):
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))


def left_shift(bits, n):
    return bits[n:] + bits[:n]


def sbox_substitute(bits48):
    """Apply the 8 S-boxes to a 48-bit string, return 32-bit output + step details."""
    output = ''
    details = []
    for i in range(8):
        block = bits48[i * 6:(i + 1) * 6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        val = SBOX[i][row][col]
        out4 = bin(val)[2:].zfill(4)
        output += out4
        details.append({
            'box': f'S{i+1}', 'input': block, 'row': row, 'col': col,
            'value': val, 'output': out4
        })
    return output, details


def feistel_f(r32, subkey48):
    expanded = permute(r32, E)
    xored = xor(expanded, subkey48)
    sub_out, sbox_details = sbox_substitute(xored)
    p_out = permute(sub_out, P)
    return p_out, {
        'input_R': r32,
        'expansion': expanded,
        'subkey': subkey48,
        'xor_result': xored,
        'sbox_details': sbox_details,
        'sbox_output': sub_out,
        'pbox_output': p_out
    }


def generate_subkeys(key64):
    """key64: 64-bit binary string (with parity bits, standard DES key)."""
    steps = {}
    pc1_out = permute(key64, PC1)
    steps['pc1'] = pc1_out
    C, D = pc1_out[:28], pc1_out[28:]
    steps['C0'] = C
    steps['D0'] = D
    subkeys = []
    round_key_steps = []
    for i in range(16):
        C = left_shift(C, SHIFTS[i])
        D = left_shift(D, SHIFTS[i])
        CD = C + D
        k = permute(CD, PC2)
        subkeys.append(k)
        round_key_steps.append({
            'round': i + 1, 'shift': SHIFTS[i], 'C': C, 'D': D, 'CD': CD, 'K': k
        })
    steps['rounds'] = round_key_steps
    return subkeys, steps


def des_process(input_bits64, key64):
    """Runs DES (single block, no padding/mode) on 64-bit binary input with 64-bit binary key.
    Returns (output64_bin, full_process_dict). Used both for encrypt and decrypt
    (decrypt = same process with reversed subkey order)."""
    subkeys, key_steps = generate_subkeys(key64)
    ip_out = permute(input_bits64, IP)
    L, R = ip_out[:32], ip_out[32:]

    rounds = []
    for i in range(16):
        subkey = subkeys[i]
        f_out, f_details = feistel_f(R, subkey)
        new_R = xor(L, f_out)
        new_L = R
        rounds.append({
            'round': i + 1,
            'L_in': L, 'R_in': R,
            'f_details': f_details,
            'L_out': new_L, 'R_out': new_R
        })
        L, R = new_L, new_R

    pre_output = R + L  # swap last round
    final_output = permute(pre_output, FP)

    process = {
        'input': input_bits64,
        'key_schedule': key_steps,
        'initial_permutation': ip_out,
        'L0': ip_out[:32], 'R0': ip_out[32:],
        'rounds': rounds,
        'pre_output_swap': pre_output,
        'final_permutation': final_output
    }
    return final_output, process


def encrypt(plaintext_hex, key_hex):
    pt = hex_to_bin(plaintext_hex, 64)
    key = hex_to_bin(key_hex, 64)
    subkeys, key_steps = generate_subkeys(key)
    ip_out = permute(pt, IP)
    L, R = ip_out[:32], ip_out[32:]
    rounds = []
    for i in range(16):
        f_out, f_details = feistel_f(R, subkeys[i])
        new_R = xor(L, f_out)
        new_L = R
        rounds.append({'round': i + 1, 'L_in': L, 'R_in': R, 'f_details': f_details,
                        'L_out': new_L, 'R_out': new_R})
        L, R = new_L, new_R
    pre_output = R + L
    cipher_bin = permute(pre_output, FP)
    cipher_hex = hex(int(cipher_bin, 2))[2:].upper().zfill(16)
    process = {
        'input': pt, 'key_schedule': key_steps, 'initial_permutation': ip_out,
        'L0': ip_out[:32], 'R0': ip_out[32:], 'rounds': rounds,
        'pre_output_swap': pre_output, 'final_permutation': cipher_bin
    }
    return cipher_hex, cipher_bin, process


def decrypt(ciphertext_hex, key_hex):
    ct = hex_to_bin(ciphertext_hex, 64)
    key = hex_to_bin(key_hex, 64)
    subkeys, key_steps = generate_subkeys(key)
    subkeys = subkeys[::-1]  # reversed order for decryption
    ip_out = permute(ct, IP)
    L, R = ip_out[:32], ip_out[32:]
    rounds = []
    for i in range(16):
        f_out, f_details = feistel_f(R, subkeys[i])
        new_R = xor(L, f_out)
        new_L = R
        rounds.append({'round': i + 1, 'L_in': L, 'R_in': R, 'f_details': f_details,
                        'L_out': new_L, 'R_out': new_R})
        L, R = new_L, new_R
    pre_output = R + L
    plain_bin = permute(pre_output, FP)
    plain_hex = hex(int(plain_bin, 2))[2:].upper().zfill(16)
    process = {
        'input': ct, 'key_schedule': key_steps, 'initial_permutation': ip_out,
        'L0': ip_out[:32], 'R0': ip_out[32:], 'rounds': rounds,
        'pre_output_swap': pre_output, 'final_permutation': plain_bin
    }
    return plain_hex, plain_bin, process
