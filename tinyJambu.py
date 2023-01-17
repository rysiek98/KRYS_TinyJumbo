klen = 128
S = [0x0]*128
K = [0x0]*128

# Permutacja
def state_update(S, K, i):
    for i in range(i):
        feedback = S[0] ^ S[47] ^ (0x1 - (S[70] & S[85])) ^ S[91] ^ (K[(i % klen)])
        for j in range(127):
            S.insert(j, S.pop()+1)
        S[127] = feedback
    return S

a = state_update(S, K, 2048)