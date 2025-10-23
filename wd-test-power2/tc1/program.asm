.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
cmp dl, -2 
and rax, 0b1111111111111 # instrumentation
cmp word ptr [r14 + rax], ax 
add ax, 26844 
and rdi, 0b1111111111111 # instrumentation
adc ebx, dword ptr [r14 + rdi] 
and rsi, 0b1111111111000 # instrumentation
lock btc dword ptr [r14 + rsi], 29 
btr edx, ecx 
and rsi, 0b1111111111111 # instrumentation
add al, byte ptr [r14 + rsi] 
or rcx, 0b1000000000000000000000000000000 # instrumentation
bsf rax, rcx 
add dil, -84 # instrumentation
and rax, 0b1111111111000 # instrumentation
lock sbb dword ptr [r14 + rax], 2 
bt di, cx 
imul eax 
and rdi, 0b1111111111111 # instrumentation
bt dword ptr [r14 + rdi], 1 
and rdi, 0b1111111111111 # instrumentation
inc byte ptr [r14 + rdi] 
dec cl 
and rdx, 0b1111111111111 # instrumentation
sbb ebx, dword ptr [r14 + rdx] 
and rsi, 0b1111111111000 # instrumentation
lock sub byte ptr [r14 + rsi], bl 
bts rbx, rsi 
and rdx, 0b1111111111111 # instrumentation
imul ax, word ptr [r14 + rdx], 32 
and rbx, 0b1111111111111 # instrumentation
btc dword ptr [r14 + rbx], 64 
imul al 
sub rax, 2078856093 
and rdx, 0b1111111111111 # instrumentation
bts word ptr [r14 + rdx], 16 
and rcx, 0b1111111111111 # instrumentation
bt word ptr [r14 + rcx], 185 
add rax, -4194304 
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit:
