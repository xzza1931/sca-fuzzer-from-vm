.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
and rsi, 0b1111111111111 # instrumentation
neg dword ptr [r14 + rsi] 
and rdx, 0b1111111111111 # instrumentation
and byte ptr [r14 + rdx], al 
and rdx, 0b1111111111111 # instrumentation
adc esi, dword ptr [r14 + rdx] 
and rdx, 0b1111111111111 # instrumentation
btr qword ptr [r14 + rdx], 1 
std  
and rcx, 0b1111111111000 # instrumentation
lock sub dword ptr [r14 + rcx], -2 
and rdi, 0b1111111111111 # instrumentation
mul byte ptr [r14 + rdi] 
and rdx, 0b1111111111111 # instrumentation
or word ptr [r14 + rdx], 0b1000000000000000 # instrumentation
bsr bx, word ptr [r14 + rdx] 
add sil, -1 # instrumentation
adc rax, 64 
jmp .bb_0.1 
.bb_0.1:
and rdx, 0b1111111111000 # instrumentation
and eax, 0b111 # instrumentation
lock btc dword ptr [r14 + rdx], eax 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
lea rbx, qword ptr [[rbx + 8]] 
lea rbx, qword ptr [[rbx - 6]] 
and rbx, 0b1111111111111 # instrumentation
and word ptr [r14 + rbx], -4 
and rbx, 0b1111111111111 # instrumentation
mov rdx, qword ptr [r14 + rbx] 
and rdx, 0b1111111111111 # instrumentation
mov rdx, qword ptr [r14 + rdx] 
movsx bx, cl 
xchg rax, rax 
setnb sil 
sub cl, 8 
inc si 
and esi, eax 
add eax, 64 
and rsi, 0b1111111111111 # instrumentation
inc qword ptr [r14 + rsi] 
and rdi, 106 
adc rbx, rbx 
and rax, 0b1111111111111 # instrumentation
or edx, dword ptr [r14 + rax] 
and rdx, 0b1111111111111 # instrumentation
cmovnle ebx, dword ptr [r14 + rdx] 
sub cl, 41 
add bl, dl 
jmp .bb_0.2 
.bb_0.2:
sub sil, 1 
bswap ecx 
and rsi, 0b1111111111111 # instrumentation
cmovl dx, word ptr [r14 + rsi] 
and rcx, 0b1111111111000 # instrumentation
lock and byte ptr [r14 + rcx], sil 
stc  
cmp al, sil 
and rdi, 0b1111111111111 # instrumentation
cmovnl di, word ptr [r14 + rdi] 
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit:
