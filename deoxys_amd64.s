#include "textflag.h"

DATA h<>+0(SB)/8, $0x000f0a050c0b0601
DATA h<>+8(SB)/8, $0x0807020d04030e09
GLOBL h<>(SB), (RODATA|NOPTR), $16

TEXT ·encryptBlockAsm(SB), $0-96
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
    MOVOU h<>(SB), X4

    // XOR the first subtweakey into the message
    MOVOU (BX), X1
    PXOR X2, X1
    PXOR X1, X0
    ADDQ $16, BX

loop:
    // Permute the tweak
    PSHUFB X4, X2

    // Get the next subtweakey
    MOVOU (BX), X1
    PXOR X2, X1
    ADDQ $16, BX

    // Encrypt
    AESENC X1, X0

    LOOP loop
end:

    // Store the result
    MOVQ out_base+72(FP), BX
    MOVOU X0, (BX)

return:
    RET
