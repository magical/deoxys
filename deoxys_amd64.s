#include "textflag.h"

DATA permutation<>+0(SB)/8, $0x000f0a050c0b0601
DATA permutation<>+8(SB)/8, $0x0807020d04030e09
GLOBL permutation<>(SB), (RODATA|NOPTR), $16

TEXT ·encryptBlockAsm(SB), NOSPLIT, $0-96
    // TODO check bounds of in, out, and tweak?

    MOVQ subkey_len+8(FP), CX
    MOVQ subkey_base+0(FP), BX

    SUBQ $1, CX
    JL return

    // Load the message and tweak
    MOVQ in_base+48(FP), AX
    MOVOU (AX), X0
    MOVQ tweak_base+24(FP), AX
    MOVOU (AX), X2

    // Load the tweak permutation
    MOVOU permutation<>(SB), X4

    // XOR the first subtweakey into the message
    MOVOU (BX), X1
    PXOR X2, X1
    ADDQ $16, BX
    PXOR X1, X0

loop:
    // Permute the tweak
    PSHUFB X4, X2

    // Get the next subtweakey
    MOVOU (BX), X1
    PXOR X2, X1
    ADDQ $16, BX

    // Encrypt
    AESENC X1, X0

    SUBQ $1, CX
    JNZ loop

    // Store the result
    MOVQ out_base+72(FP), BX
    MOVOU X0, (BX)

return:
    RET
