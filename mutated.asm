.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
add dil, 42 # instrumentation
push rbx 
mov rax, 0x55555555 
jz .bb_0.1 
jmp .exit_0 
.bb_0.1:
mov rax, 0x55555555 
jmp .exit_0 
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit:
