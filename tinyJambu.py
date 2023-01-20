
klen = 128              # key length in bits
S = [0x0]*128           # state of the permutation
K = [0x0]*128           # key
N = [0] * 96            # nonce
AD = [0]*32             # associated data
FB_n = [0, 0, 1]        # FrameBits for nonce = 1
FB_ad = [0, 1, 1]       # FrameBits for associated data = 3
FB_pc = [1, 0, 1]       # FrameBits for plaintext and ciphertext = 5
FB_f = [1, 1, 1]        # FrameBits for finalization = 5


# Permutation
def state_update(S, K, i):
    for i in range(i):
        feedback = S[0] ^ S[47] ^ (0x1 - (S[70] & S[85])) ^ S[91] ^ (K[(i % klen)])
        for j in range(127):
            S.insert(j, S.pop()+1)
        S[127] = feedback
    return S


# Initialization
S = state_update(S, K, 1024)


def nonce_init(S, K, FB_n):
    for i in range(3):
        S[36:39] = list(a ^ b for a, b in zip(S[36:39], FB_n))
        S = state_update(S, K, 640)
        S[96:128] = list(a ^ b for a, b in zip(S[96:128], N[32 * i : 32 * i + 32]))
    return S


# Processing associated data
def process_associated_data(S, K, FB_ad, AD):
    for j in range (1):
        S[36:38] = list(a ^ b for a, b in zip(S[36:38], FB_ad))
        S = state_update(S, K, 640)
        S[96:127] = list(a ^ b for a, b in zip(S[96:127], AD[32*j:32*j+31]))
    return S


a = state_update(S, K, 2048)


# Processing plain text
def process_plain_text(msg):
    mlen = msg.__len__()    # message length
    c = []                  # ciphertext

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
        lenp = mlen % 32                # number of bits in partial block
        startp = mlen - lenp            # starting position of partial block

        # the length (bytes) of the last partial block is XORed to the state
        S[96: 96 + lenp] = list(a ^ b for a, b in zip(S[96: 96 + lenp], msg[startp:mlen]))
        c[startp:mlen] = list(a ^ b for a, b in zip(S[64: 64 + lenp], msg[startp:mlen]))
        S[32] ^= lenp

    return c
