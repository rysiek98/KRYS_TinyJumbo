from random import getrandbits

FB_n = [0, 0, 1]  # FrameBits for nonce = 1
FB_ad = [0, 1, 1]  # FrameBits for associated data = 3
FB_pc = [1, 0, 1]  # FrameBits for plaintext and ciphertext = 5
FB_f = [1, 1, 1]  # FrameBits for finalization = 5
klen = 128  # key length in bits


# Permutation
def state_update(S, K, i):
    for i in range(i):
        feedback = S[0] ^ S[47] ^ (0x1 - (S[70] & S[85])) ^ S[91] ^ (K[(i % klen)])
        S[0:127] = S[1:128]
        S[127] = feedback
    return S


def nonce_init(S, K, N):
    for i in range(3):
        S[36:39] = list(a ^ b for a, b in zip(S[36:39], FB_n))
        S = state_update(S, K, 640)
        S[96:128] = list(a ^ b for a, b in zip(S[96:128], N[32 * i: 32 * i + 32]))
    return S


# Processing associated data
def process_associated_data(S, K, AD):
    for j in range(1):
        S[36:38] = list(a ^ b for a, b in zip(S[36:38], FB_ad))
        S = state_update(S, K, 640)
        S[96:127] = list(a ^ b for a, b in zip(S[96:127], AD[32 * j:32 * j + 31]))
    return S


def process_plain_text(msg, S, K):
    mlen = msg.__len__()  # message length
    c = []  # ciphertext

    # Processing full blocks of plain_text (i - block index)
    if mlen >= 32:
        for i in range(int(mlen / 32)):
            S[36:39] = list(a ^ b for a, b in zip(S[36:39], FB_pc))
            S = state_update(S, K, 1024)
            S[96:128] = list(a ^ b for a, b in zip(S[96:128], msg[32 * i: 32 * i + 32]))
            c[32 * i: 32 * i + 32] = list(a ^ b for a, b in zip(S[64:96], msg[32 * i: 32 * i + 32]))

    # Processing last block of plain_text if it is a partial block
    if mlen % 32 > 0:
        S[36:39] = list(a ^ b for a, b in zip(S[36:39], FB_pc))
        S = state_update(S, K, 1024)
        lenp = mlen % 32
        startp = mlen - lenp

        # the length (bytes) of the last partial block is XORed to the stat
        S[96: 96 + lenp] = list(a ^ b for a, b in zip(S[96: 96 + lenp], msg[startp:mlen]))
        c[startp:mlen] = list(a ^ b for a, b in zip(S[64: 64 + lenp], msg[startp:mlen]))
        S[32] ^= lenp

    return c


def decrypt_process_plain_test(ct, S, K):
    M = []
    clen = len(ct)
    if clen >= 32:
        for k in range(int(clen / 32)):
            S[36:39] = list(a ^ b for a, b in zip(S[36:39], FB_pc))
            S = state_update(S, K, 1024)
            M[32 * k:32 * k + 32] = list(a ^ b for a, b in zip(S[64:96], ct[32 * k:32 * k + 32]))
            S[96:128] = list(a ^ b for a, b in zip(S[96:128], M[32 * k:32 * k + 32]))

    if clen % 32 > 0:
        S[36:39] = list(a ^ b for a, b in zip(S[36:39], FB_pc))
        S = state_update(S, K, 1024)
        lenp = clen % 32
        startp = clen - lenp
        M[startp:clen] = list(a ^ b for a, b in zip(S[64:64 + lenp], ct[startp:clen]))
        S[96:96 + lenp] = list(a ^ b for a, b in zip(S[96:96 + lenp], M[startp:clen]))
        S[32] ^= lenp
    return M


def bitfield(n, wanted_len):
    bits = [1 if digit == '1' else 0 for digit in bin(n)[2:]]
    while len(bits) != wanted_len:
        bits.insert(0, 0)
    return bits


def bit_array_to_bytes(arr):

    if len(arr) % 8 != 0:
        raise ValueError()

    byte_array = []
    for i in range(0, len(arr), 8):
        byte = arr[i:i + 8]
        value = 0
        for x in range(8):
            value <<= 1
            value += byte[x]
        byte_array.append(value)
    return bytes(byte_array)


def encryption(msg, K, N, AD):
    S = [0x0] * 128
    S = state_update(S, K, 1024)
    nonce_init(S, K, N)
    process_associated_data(S, K, AD)
    S = state_update(S, K, 1024)
    return process_plain_text(msg, S, K)


def decryption(ct, K, N, AD):
    S = [0x0] * 128
    S = state_update(S, K, 1024)
    nonce_init(S, K, N)
    process_associated_data(S, K, AD)
    S = state_update(S, K, 1024)
    return decrypt_process_plain_test(ct, S, K)


def main():
    N = [0] * 96  # nonce
    AD = [0] * 32  # associated data

    K = bitfield(getrandbits(128), 128)

    message = []
    with open("message.txt", encoding="utf-8") as message_file:
        message = message_file.read()
    message_bits = ''.join(format(ord(i), '08b') for i in message)
    message_bits = [int(x) for x in message_bits]

    ciphertext = encryption(message_bits, K, N, AD)

    decrypted_bits = decryption(ciphertext, K, N, AD)

    decrypted_message = bit_array_to_bytes(decrypted_bits).decode("utf-8")

    print(message[:40])
    print(decrypted_message[:40])
    print(message == decrypted_message)


if __name__ == "__main__":
    main()
