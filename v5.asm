.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
and rdi, 0b1111111111111 # instrumentation
xor qword ptr [r14 + rdi], rbx 
and rbx, 0b1111111111111 # instrumentation
setz byte ptr [r14 + rbx] 
bts ebx, ecx 
and rbx, 0b1111111111000 # instrumentation
lock sub dword ptr [r14 + rbx], edi 
stc  
and rbx, 0b1111111111111 # instrumentation
and rsi, 0b1111111111111 # instrumentation
sub word ptr [r14 + rsi], 2 
cmovs di, si 
and rsp, 0b1111111111111 # instrumentation
add rsp, r14 # instrumentation
call .function_1 
sub rsp, r14 # instrumentation
movsx ebx, dx 
add eax, 388155814 
inc cl 
movzx eax, ax 
xor dl, cl 
and rdx, 0b1111111111111 # instrumentation
mov rdx, qword ptr [r14 + rdx] 
cmp ebx, 16 
and rax, 0b1111111111111 # instrumentation
cmovbe si, word ptr [r14 + rax] 
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
.section .data.main
.function_1:
.bb_1.0:
add dil, 52 # instrumentation
cmovnz cx, dx 
xor cl, cl 
and rsi, 0b1111111111111 # instrumentation
movzx bx, byte ptr [r14 + rsi] 
and rdi, 0b1111111111111 # instrumentation
and dl, byte ptr [r14 + rdi] 
movzx esi, si 
and rax, 0b1111111111111 # instrumentation
movzx edx, byte ptr [r14 + rax] 
cmovbe ax, di 
add al, -48 
lea rdx, qword ptr [rip + .function_2] 
and rsp, 0b1111111111111 # instrumentation
mov qword ptr [r14 + rsp], rdx 
and rsp, 0b1111111111111 # instrumentation
add rsp, r14 # instrumentation
ret  
sub rsp, r14 # instrumentation
.exit_1:
.section .data.main
.function_2:
.bb_2.0:
add sil, 99 # instrumentation
and rax, 0b1111111111111 # instrumentation
sbb word ptr [r14 + rax], 1 
add rdx, -8 
and rcx, 0b1111111111111 # instrumentation
or qword ptr [r14 + rcx], -64 
and rcx, 0b1111111111111 # instrumentation
test qword ptr [r14 + rcx], rdi 
bswap ebx 
and rcx, 0b1111111111000 # instrumentation
lock xor byte ptr [r14 + rcx], al 
and rax, 0b1111111111000 # instrumentation
lock xor byte ptr [r14 + rax], 22 
and rbx, 0b1111111111111 # instrumentation
add dword ptr [r14 + rbx], 32 
.exit_2:
jmp .test_case_exit 
.section .data.main
.test_case_exit:
