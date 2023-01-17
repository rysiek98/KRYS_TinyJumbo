klen = 128
S = [0x0]*128
K = [0x0]*128
N = [0] * 96
FB_n = [0, 0, 1]

# Permutacja
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

a = state_update(S, K, 2048)