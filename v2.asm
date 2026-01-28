.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
cld  # instrumentation
sub eax, -67108864 
test edx, -536870912 
and rdi, 0b1111111111111 # instrumentation
add rdi, r14 # instrumentation
and rsi, 0b1111111111111 # instrumentation
add rsi, r14 # instrumentation
and rcx, 0xff # instrumentation
add rcx, 1 # instrumentation
repe movsw  
sub rsi, r14 # instrumentation
sub rdi, r14 # instrumentation
and rbx, 0b1111111111111 # instrumentation
bt word ptr [r14 + rbx], 67 
add dil, -8 # instrumentation
setle al 
and rdx, 0b1111111111111 # instrumentation
btc dword ptr [r14 + rdx], 90 
cmovz rcx, rdx 
and sil, -2 
cmpxchg bx, si 
xor rax, 16 
and rax, 0b1111111111111 # instrumentation
or al, byte ptr [r14 + rax] 
cmovnp dx, dx 
and rcx, 0b1111111111111 # instrumentation
not word ptr [r14 + rcx] 
and rcx, 0b1111111111000 # instrumentation
lock sub byte ptr [r14 + rcx], cl 
cmovno edi, esi 
and rcx, 0b1111111111000 # instrumentation
lock sbb word ptr [r14 + rcx], dx 
lea rdx, qword ptr [rip + .bb_0.1] 
lea rsi, qword ptr [rip + .bb_0.2] 
cmovz rsi, rdx 
jmp rsi 
.bb_0.1:
add sil, -95 # instrumentation
cmovp esi, eax 
or rsi, 0b1000000000000000000000000000000 # instrumentation
bsr rsi, rsi 
cmpxchg dx, ax 
and rsi, 0b1111111111000 # instrumentation
lock cmpxchg byte ptr [r14 + rsi], cl 
and rax, 0b1111111111000 # instrumentation
lock btr word ptr [r14 + rax], 97 
and rsi, 0b1111111111111 # instrumentation
imul word ptr [r14 + rsi] 
add dil, -8 # instrumentation
nop  
and rdx, 0b1111111111111 # instrumentation
cmovnp rsi, qword ptr [r14 + rdx] 
.bb_0.2:
cld  # instrumentation
or al, -16 
and rcx, 0b1111111111111 # instrumentation
cmovz edx, dword ptr [r14 + rcx] 
and rbx, 0b1111111111111 # instrumentation
and edi, 0b111 # instrumentation
btr dword ptr [r14 + rbx], edi 
and rbx, 0b1111111111111 # instrumentation
sbb qword ptr [r14 + rbx], rbx 
and rsi, 0b1111111111111 # instrumentation
add rsi, r14 # instrumentation
lodsw  
sub rsi, r14 # instrumentation
and rax, 0b1111111111111 # instrumentation
cmovnb ax, word ptr [r14 + rax] 
and rbx, 0b1111111111111 # instrumentation
xor rdi, qword ptr [r14 + rbx] 
and rbx, 0b1111111111000 # instrumentation
lock and byte ptr [r14 + rbx], cl 
mov rdx, 0 
mov rsi, 0 
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit:
