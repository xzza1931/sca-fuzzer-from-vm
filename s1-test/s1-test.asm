.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
mov rax, 0x55555555
mov rdx, 0xAAAAAAAA
xor rsi, rsi
mov rdi, 0x12345678
and rax, 0x0F0F0F0F
or rdx, 0xF0F0F0F
xor rsi, 0x33333333
not rdi
add rax, 0x11111111
sub rdx, 0x22222222
xor rcx, 0x44444444
mov qword ptr [R14 + 0x100], rax
mov qword ptr [R14 + 0x108], rdx
mov qword ptr [R14 + 0x110], rsi
mov qword ptr [R14 + 0x118], rdi

mov rax, 0x55555555
mov rdx, 0xAAAAAAAA
xor rsi, rsi
mov rdi, 0x12345678
and rax, 0x0F0F0F0F
or rdx, 0xF0F0F0F
xor rsi, 0x33333333
not rdi
add rax, 0x11111111
sub rdx, 0x22222222
xor rcx, 0x44444444
mov qword ptr [R14 + 0x100], rax
mov qword ptr [R14 + 0x108], rdx
mov qword ptr [R14 + 0x110], rsi
mov qword ptr [R14 + 0x118], rdi

mov rax, 0x55555555
mov rdx, 0xAAAAAAAA
xor rsi, rsi
mov rdi, 0x12345678
and rax, 0x0F0F0F0F
or rdx, 0xF0F0F0F
xor rsi, 0x33333333
not rdi
add rax, 0x11111111
sub rdx, 0x22222222
xor rcx, 0x44444444
mov qword ptr [R14 + 0x100], rax
mov qword ptr [R14 + 0x108], rdx
mov qword ptr [R14 + 0x110], rsi
mov qword ptr [R14 + 0x118], rdi
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit: