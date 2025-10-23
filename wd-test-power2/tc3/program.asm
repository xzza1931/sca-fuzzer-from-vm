.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
and rdx, 0b1111111111111 # instrumentation
bts dword ptr [r14 + rdx], 104 
and rdi, 0b1111111111111 # instrumentation
imul bx, word ptr [r14 + rdi] 
cmp rbx, rbx 
imul al 
adc rax, 1991935700 
and rcx, 0b1111111111000 # instrumentation
lock sbb byte ptr [r14 + rcx], -32 
adc rax, 8388608 
bt bx, di 
sbb dl, 106 
or bx, 0b1000000000000000 # instrumentation
bsf cx, bx 
add ax, -2 
or rdi, 0b1000000000000000000000000000000 # instrumentation
bsf rbx, rdi 
mul cl 
sbb ebx, -32 
jmp .bb_0.1 
.bb_0.1:
and rcx, 0b1111111111111 # instrumentation
bt dword ptr [r14 + rcx], 12 
cmp edx, edi 
imul edx, ebx 
btc edx, edi 
and rax, 0b1111111111111 # instrumentation
bt qword ptr [r14 + rax], 128 
imul rcx, rdx, 107 
and rdx, 0b1111111111000 # instrumentation
lock add word ptr [r14 + rdx], bx 
and rcx, 0b1111111111111 # instrumentation
imul bx, word ptr [r14 + rcx], 107 
bts dx, 32 
neg bx 
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit:
