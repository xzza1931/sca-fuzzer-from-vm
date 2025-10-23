.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
add di, cx 
and rdx, 0b1111111111111 # instrumentation
cmp bx, word ptr [r14 + rdx] 
and rbx, 0b1111111111000 # instrumentation
lock sbb word ptr [r14 + rbx], dx 
and rsi, 0b1111111111000 # instrumentation
and esi, 0b111 # instrumentation
lock btc dword ptr [r14 + rsi], esi 
and rdi, 0b1111111111111 # instrumentation
add rax, qword ptr [r14 + rdi] 
bts bx, di 
sbb ax, -32 
bts eax, 4 
and rcx, 0b1111111111111 # instrumentation
add sil, byte ptr [r14 + rcx] 
sbb sil, -1 
and rsi, 0b1111111111111 # instrumentation
add eax, dword ptr [r14 + rsi] 
dec edi 
and rax, 0b1111111111000 # instrumentation
and ecx, 0b111 # instrumentation
lock btc dword ptr [r14 + rax], ecx 
and rsi, 0b1111111111111 # instrumentation
cmp rdx, qword ptr [r14 + rsi] 
imul ebx, esi 
and rax, 0b1111111111111 # instrumentation
or word ptr [r14 + rax], 0b1000000000000000 # instrumentation
bsf si, word ptr [r14 + rax] 
dec dl 
sub ebx, -1 
sbb dl, 11 
sub rax, 1444852532 
and rdx, 0b1111111111111 # instrumentation
imul dx, word ptr [r14 + rdx], -77 
and rbx, 0b1111111111111 # instrumentation
dec byte ptr [r14 + rbx] 
neg bx 
and rsi, 0b1111111111111 # instrumentation
imul rcx, qword ptr [r14 + rsi] 
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit:
