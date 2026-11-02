        .text
        .globl _start
_start:
        bl callee
        b done
callee:
        blr
done:
        nop
