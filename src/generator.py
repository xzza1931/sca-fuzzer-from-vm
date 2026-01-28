"""
File: Test Case Generation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import math
import random
import abc
import re
from typing import List, Tuple, Optional
from subprocess import CalledProcessError, run
from copy import deepcopy

from .isa_loader import InstructionSet
from .interfaces import Generator, TestCase, Operand, RegisterOperand, FlagsOperand, \
    MemoryOperand, ImmediateOperand, AgenOperand, LabelOperand, OT, Instruction, BasicBlock, \
    Function, OperandSpec, InstructionSpec, CondOperand, Actor, ActorMode, ActorPL, \
    NotSupportedException
from .util import Logger
from .config import CONF

import json
import os
import copy


# ==================================================================================================
# Generator Interface
# ==================================================================================================
class Pass(abc.ABC):

    def __init__(self) -> None:
        self.LOG = Logger()
        super().__init__()

    @abc.abstractmethod
    def run_on_test_case(self, test_case: TestCase) -> None:
        pass


class Printer(abc.ABC):
    prologue_template: List[str]
    epilogue_template: List[str]

    @abc.abstractmethod
    def print(self, test_case: TestCase, outfile: str, print_exit: bool = True) -> None:
        pass


class ConfigurableGenerator(Generator, abc.ABC):
    """
    The interface description for Generator classes.
    """
    instruction_set: InstructionSet
    test_case: TestCase
    parsed_template: Optional[TestCase] = None
    passes: List[Pass]  # set by subclasses
    printer: Printer  # set by subclasses

    LOG: Logger  # name capitalized to make logging easily distinguishable from the main logic

    def __init__(self, instruction_set: InstructionSet, seed: int):
        super().__init__(instruction_set, seed)
        self.LOG = Logger()
        self.LOG.dbg_gen_instructions(instruction_set.instructions)
        self.control_flow_instructions = \
            [i for i in self.instruction_set.instructions if i.control_flow]
        assert self.control_flow_instructions or CONF.max_successors_per_bb <= 1, \
               "The instruction set is insufficient to generate a test case"
        '''
        def dump_instruction_list(filename, instr_list, title):
            with open(filename, "w") as f:
                f.write(f"==== {title} ====\n\n")
                for instr in instr_list:
                    try:
                        data = instr.__dict__  # 把对象的所有字段转成字典
                        f.write(json.dumps(data, indent=4, ensure_ascii=False))
                        f.write("\n\n")
                    except Exception as e:
                        f.write(f"无法序列化 {instr}: {e}\n\n")
        dump_instruction_list("control_flow_instructions.txt",
                              self.control_flow_instructions,
                              "Control Flow Instructions")
        '''

        self.non_control_flow_instructions = \
            [i for i in self.instruction_set.instructions if not i.control_flow]
        assert self.non_control_flow_instructions, \
            "The instruction set is insufficient to generate a test case"

        self.non_memory_access_instructions = \
            [i for i in self.non_control_flow_instructions if not i.has_mem_operand]
        if CONF.avg_mem_accesses != 0:
            memory_access_instructions = \
                [i for i in self.non_control_flow_instructions if i.has_mem_operand]
            self.load_instruction = [i for i in memory_access_instructions if not i.has_write]
            self.store_instructions = [i for i in memory_access_instructions if i.has_write]
            assert self.load_instruction or self.store_instructions, \
                "The instruction set does not have memory accesses while `avg_mem_accesses > 0`"
        else:
            self.load_instruction = []
            self.store_instructions = []

    def set_seed(self, seed: int) -> None:
        self._state = seed

    def update_seed(self) -> None:
        if self._state == 0:
            self._state = random.randint(1, 1000000)
            self.LOG.inform("prog_gen",
                            f"Setting program_generator_seed to random value: {self._state}")
        random.seed(self._state)
        self._state += 1

    def create_test_case(self, asm_file: str, disable_assembler: bool = False) -> TestCase:
        #print("\n=======================  generate.py create_test_case()  ==================")
        self.test_case = TestCase(self._state)
        if not asm_file:
            asm_file = 'generated.asm'

        # set seeds
        self.update_seed()

        # create actors
        if len(CONF._actors) != 1:
            self.LOG.error("Generation of test cases with multiple actors is not yet supported")
        self.create_actors(self.test_case)

        # create the main function
        default_actor = self.test_case.actors["main"]
        func = self.generate_function(".function_0", default_actor, self.test_case)

        # fill the function with instructions
        self.add_terminators_in_function(func)
        self.add_instructions_in_function(func)

        # add it to the test case
        self.test_case.functions.append(func)

        # process the test case
        for p in self.passes:
            p.run_on_test_case(self.test_case)

        # add symbols to test case
        self.add_required_symbols(self.test_case)

        self.printer.print(self.test_case, asm_file)
        self.test_case.asm_path = asm_file

        if disable_assembler:
            return self.test_case

        bin_file = asm_file[:-4]
        obj_file = bin_file + ".o"
        self.assemble(asm_file, obj_file, bin_file)
        self.test_case.bin_path = bin_file
        self.test_case.obj_path = obj_file

        self.get_elf_data(self.test_case, obj_file)

        return self.test_case
    
    def create_v1_test_case(self, asm_file: str, disable_assembler: bool = False) -> TestCase:
        #print("\n=======================  generate.py create_test_case()  ==================")
        self.test_case = TestCase(self._state)
        if not asm_file:
            asm_file = 'generated.asm'

        # set seeds
        self.update_seed()

        # create actors
        if len(CONF._actors) != 1:
            self.LOG.error("Generation of test cases with multiple actors is not yet supported")
        self.create_actors(self.test_case)

        # create the main function
        default_actor = self.test_case.actors["main"]
        func = self.generate_function(".function_0", default_actor, self.test_case)

        # fill the function with instructions
        self.add_terminators_in_function(func)
        self.add_instructions_in_function(func)

        # add it to the test case
        self.test_case.functions.append(func)

        # process the test case
        for p in self.passes:
            p.run_on_test_case(self.test_case)

        # add symbols to test case
        self.add_required_symbols(self.test_case)

        self.printer.print(self.test_case, asm_file)
        self.test_case.asm_path = asm_file

        if disable_assembler:
            return self.test_case

        bin_file = asm_file[:-4]
        obj_file = bin_file + ".o"
        self.assemble(asm_file, obj_file, bin_file)
        self.test_case.bin_path = bin_file
        self.test_case.obj_path = obj_file

        self.get_elf_data(self.test_case, obj_file)

        return self.test_case
    
    def create_v2_test_case(self, asm_file: str, disable_assembler: bool = False) -> TestCase:
        self.test_case = TestCase(self._state)
        if not asm_file:
            asm_file = 'v2.asm'

        # set seeds
        self.update_seed()

        # create actors
        if len(CONF._actors) != 1:
            self.LOG.error("Generation of test cases with multiple actors is not yet supported")
        self.create_actors(self.test_case)

        # create the main function
        default_actor = self.test_case.actors["main"]
        # 我不需要生成有向无环图，我要生成三个基本块，基本块之间无需通过label跳转连接
        func = self.generate_function_for_v2(".function_0", default_actor, self.test_case)

        # fill the function with instructions
        self.add_instructions_in_v2_function(func)

        # 在第一个基本块的末尾加入必要的指令片段
        # lea rdx, qword ptr [rip + .bb_0.1]
        lea_inst = Instruction(
            name="lea",
            is_instrumentation=False,
            category="BASE-MISC",
            control_flow=False
        )
        rdx_op = RegisterOperand("rdx", src=False, dest=True, width=64)
        lea_inst.add_op(rdx_op)
        agen_op = AgenOperand("rip + .bb_0.1", 64)
        lea_inst.add_op(agen_op)
        func[0].insert_after(func[0].get_last(), lea_inst)

        # lea rsi, qword ptr [rip + .bb_0.2]
        lea_inst = Instruction(
            name="lea",
            is_instrumentation=False,
            category="BASE-MISC",
            control_flow=False
        )
        rdx_op = RegisterOperand("rsi", src=False, dest=True, width=64)
        lea_inst.add_op(rdx_op)
        agen_op = AgenOperand("rip + .bb_0.2", 64)
        lea_inst.add_op(agen_op)
        func[0].insert_after(func[0].get_last(), lea_inst)

        # cmovz rsi, rdx
        cmovz_inst = Instruction(
            name="cmovz",
            is_instrumentation=False,
            category="BASE-CMOV",
            control_flow=False
        )
        cmovz_inst.add_op(RegisterOperand("rsi", src=False, dest=True, width=64))
        cmovz_inst.add_op(RegisterOperand("rdx", src=True, dest=False, width=64))
        flags = FlagsOperand(["", "", "", "r", "", "", "", "", ""]) 
        cmovz_inst.add_op(flags, implicit=True)
        func[0].insert_after(func[0].get_last(), cmovz_inst)

        # jmp rsi
        jmp_inst = Instruction(name="jmp", is_instrumentation=False, category="BASE-UNCOND_BR", control_flow=True)
        rsi_op = RegisterOperand(value="rsi", width=64, src=True, dest=False)
        rip_op = RegisterOperand(value="rip", width=64, src=False, dest=True)
        jmp_inst.add_op(rsi_op)
        jmp_inst.add_op(rip_op, implicit=True)
        func[0].insert_after(func[0].get_last(), jmp_inst)

        # mov rdx, 0
        mov_rdx_inst = Instruction(
            name="mov",
            is_instrumentation=False,
            category="BASE-DATAXFER",
            control_flow=False
        )
        mov_rdx_inst.add_op(RegisterOperand("rdx", src=False, dest=True, width=64))
        mov_rdx_inst.add_op(ImmediateOperand("0", width=32))
        last_bb = func[-1]
        last_bb.insert_after(last_bb.get_last(), mov_rdx_inst)

        # mov rsi, 0
        mov_rsi_inst = Instruction(
            name="mov",
            is_instrumentation=False,
            category="BASE-DATAXFER",
            control_flow=False
        )
        mov_rsi_inst.add_op(RegisterOperand("rsi", src=False, dest=True, width=64))
        mov_rsi_inst.add_op(ImmediateOperand("0", width=32))
        last_bb.insert_after(last_bb.get_last(), mov_rsi_inst)

        # add it to the test case
        self.test_case.functions.append(func)

        # process the test case
        for p in self.passes:
            #print("------- Running pass:", p.__class__.__name__, " -------")
            p.run_on_test_case(self.test_case)

        #self.printer.print(self.test_case, asm_file)
        #breakpoint()
        # add symbols to test case
        self.add_required_symbols(self.test_case)

        self.printer.print(self.test_case, asm_file)
        self.test_case.asm_path = asm_file
        #breakpoint()
        if disable_assembler:
            return self.test_case
        
        bin_file = asm_file[:-4]
        obj_file = bin_file + ".o"
        self.assemble(asm_file, obj_file, bin_file)
        self.test_case.bin_path = bin_file
        self.test_case.obj_path = obj_file

        self.get_elf_data(self.test_case, obj_file)

        return self.test_case

    def create_v4_test_case(self, asm_file: str, disable_assembler: bool = False) -> TestCase:
        #print("\n=======================  generate.py create_v4_test_case()  ==================")
        self.test_case = TestCase(self._state)
        if not asm_file:
            asm_file = 'v4.asm'

        # set seeds
        self.update_seed()

        # create actors
        if len(CONF._actors) != 1:
            self.LOG.error("Generation of test cases with multiple actors is not yet supported")
        self.create_actors(self.test_case)

        # create the main function
        default_actor = self.test_case.actors["main"]
        func = self.generate_function(".function_0", default_actor, self.test_case)

        # fill the function with instructions
        self.add_terminators_in_function(func)
        self.add_instructions_in_v4_function(func)

        # add it to the test case
        self.test_case.functions.append(func)

        #self.printer.print(self.test_case, asm_file)
        #breakpoint()
        # process the test case
        for p in self.passes:
            p.run_on_test_case(self.test_case)

        # add symbols to test case
        self.add_required_symbols(self.test_case)

        self.printer.print(self.test_case, asm_file)
        self.test_case.asm_path = asm_file

        if disable_assembler:
            return self.test_case

        bin_file = asm_file[:-4]
        obj_file = bin_file + ".o"
        self.assemble(asm_file, obj_file, bin_file)
        self.test_case.bin_path = bin_file
        self.test_case.obj_path = obj_file

        self.get_elf_data(self.test_case, obj_file)

        return self.test_case
    
    def create_v5_test_case(self, asm_file: str, disable_assembler: bool = False) -> TestCase:
        self.test_case = TestCase(self._state)
        if not asm_file:
            asm_file = 'v5.asm'

        # set seeds
        self.update_seed()

        # create actors
        if len(CONF._actors) != 1:
            self.LOG.error("Generation of test cases with multiple actors is not yet supported")
        self.create_actors(self.test_case)

         # create the main function
        default_actor = self.test_case.actors["main"]

        #v5需要三个函数，在yaml里需要设置每个函数只有一个bb，防止引入跳转指令
        functions = []
        for i in range(3):
            func_name = f".function_{i}"
            if i == 2:
                func = self.generate_function(func_name, default_actor, self.test_case)  
            else:
                func = self.generate_function_without_exitbb(func_name, default_actor, self.test_case)
            functions.append(func)
        
        #breakpoint()
        # fill the function with instructions
        #第一个函数填充指令
        self.add_instructions_in_v5_function(functions[0],CONF.program_size // 4 )
        #这里需要插入第一个片段
        # call .function_1
        call_inst = Instruction(
            name="call",
            is_instrumentation=False,
            category="BASE-CALL",
            control_flow=True
        )
        call_inst.add_op(LabelOperand(".function_1"))
        call_inst.add_op(RegisterOperand("rsp", src=True, dest=True, width=64), implicit=True)
        call_inst.add_op(RegisterOperand("rip", src=True, dest=True, width=64), implicit=True)
        call_inst.add_op(MemoryOperand("rsp", src=False, dest=True, width=64), implicit=True)
        functions[0][0].insert_after(functions[0][0].get_last(), call_inst)

        lfence_inst = Instruction(
            "lfence",
            is_instrumentation=False,
            category="SSE2-MISC",
            control_flow=False
        )
        #functions[0][0].insert_after(functions[0][0].get_last(), lfence_inst)

        self.add_instructions_in_v5_function(functions[0],CONF.program_size // 4 )

        #第二个函数填充指令
        #self.add_instructions_in_v5_function(functions[1],CONF.program_size // 4 )
        #这里需要插入两条指令
        # lea rdx, qword ptr [rip + .function_2]
        # mov qword ptr [rsp], rdx
        lea_inst = Instruction(
            name="lea",
            is_instrumentation=False,
            category="BASE-MISC",
            control_flow=False
        )
        rdx_op = RegisterOperand("rdx", src=False, dest=True, width=64)
        lea_inst.add_op(rdx_op)
        agen_op = AgenOperand("rip + .function_2", 64)
        lea_inst.add_op(agen_op)
        functions[1][0].insert_after(functions[1][0].get_last(), lea_inst)

        mov_instr = Instruction(
            name="mov",
            is_instrumentation=False,
            category="BASE-DATAXFER",
            control_flow=False
        )
        mem_op = MemoryOperand(
            address="rsp",
            width=64,
            src=False,   # 内存写入，不是读取
            dest=True
        )
        mov_instr.add_op(mem_op)
        reg_op = RegisterOperand(
            value="rdx",
            width=64,
            src=True,    # 从寄存器读取
            dest=False
        )
        mov_instr.add_op(reg_op)
        functions[1][0].insert_after(functions[1][0].get_last(), mov_instr)

        #这里需要插入ret指令
        ret_instr = Instruction(
            name="ret",
            is_instrumentation=False,
            category="BASE-RET",
            control_flow=True
        )
        rsp_op = RegisterOperand("rsp", width=64, src=True, dest=True)
        rip_op = RegisterOperand("rip", width=64, src=False, dest=True)
        mem_rsp_op = MemoryOperand("rsp", width=64, src=True, dest=False)
        ret_instr.add_op(rsp_op, implicit=True)
        ret_instr.add_op(rip_op, implicit=True)
        ret_instr.add_op(mem_rsp_op, implicit=True)
        functions[1][0].insert_after(functions[1][0].get_last(), ret_instr)

        #第三个函数填充指令
        self.add_instructions_in_v5_function(functions[2],CONF.program_size // 4 )

        # add it to the test case
        for i in range(3):
            self.test_case.functions.append(functions[i])

        # process the test case
        for p in self.passes:
            print("------- Running pass:", p.__class__.__name__, " -------")
            p.run_on_test_case(self.test_case)

        #self.printer.print(self.test_case, asm_file)
        #breakpoint()
        # add symbols to test case
        self.add_required_symbols(self.test_case)

        self.printer.print(self.test_case, asm_file)
        self.test_case.asm_path = asm_file

        if disable_assembler:
            return self.test_case
        
        bin_file = asm_file[:-4]
        obj_file = bin_file + ".o"
        self.assemble(asm_file, obj_file, bin_file)
        self.test_case.bin_path = bin_file
        self.test_case.obj_path = obj_file

        self.get_elf_data(self.test_case, obj_file)

        return self.test_case


    def create_phased_test_case(self, asm_file: str, disable_assembler: bool = False) -> TestCase:
        self.test_case = TestCase(self._state)
        if not asm_file:
            asm_file = 'phased_test_case.asm'

        # set seeds
        self.update_seed()  

        # create actors
        if len(CONF._actors) != 1:
            self.LOG.error("Generation of test cases with multiple actors is not yet supported")
        self.create_actors(self.test_case)

        # create the main function
        default_actor = self.test_case.actors["main"]
        func = self.generate_function_for_phased_test_case(".function_0", default_actor, self.test_case)

        # fill the function with instructions
        self.add_terminators_in_function(func)#第一个后继一定是瞬态块
        #接下来要为基本块生成指令
        #++++++++++++++++++++++++++++++++++++

        # add it to the test case
        self.test_case.functions.append(func)

        # process the test case
        for p in self.passes:
            p.run_on_test_case(self.test_case)

        # add symbols to test case
        self.add_required_symbols(self.test_case)

        self.printer.print(self.test_case, asm_file)
        self.test_case.asm_path = asm_file

        if disable_assembler:
            return self.test_case

        bin_file = asm_file[:-4]
        obj_file = bin_file + ".o"
        self.assemble(asm_file, obj_file, bin_file)
        self.test_case.bin_path = bin_file
        self.test_case.obj_path = obj_file

        self.get_elf_data(self.test_case, obj_file)

        return self.test_case


    def create_test_case_from_template(self, template: str) -> TestCase:
        self.update_seed()

        if self.parsed_template:
            test_case = deepcopy(self.parsed_template)
        else:
            test_case = self.asm_parser.parse_file(template)
            self.parsed_template = deepcopy(test_case)

        self.test_case = test_case
        for func in test_case.functions:
            for bb in func:
                for instr in bb:
                    instr.is_from_template = True

        self.expand_template(test_case)
        for p in self.passes:
            p.run_on_test_case(self.test_case)

        asm_file = 'generated.asm'
        self.printer.print(self.test_case, asm_file, False)
        test_case.asm_path = asm_file

        bin_file = asm_file[:-4]
        obj_file = bin_file + ".o"
        self.assemble(asm_file, obj_file, bin_file)
        self.test_case.bin_path = bin_file
        self.test_case.obj_path = obj_file


        self.test_case.symbol_table = []
        self.get_elf_data(self.test_case, obj_file)
        return test_case

    @staticmethod
    def assemble(asm_file: str, obj_file: str, bin_file: str) -> None:
        """Assemble the test case into a stripped binary"""

        def pretty_error_msg(error_msg):
            with open(asm_file, "r") as f:
                lines = f.read().split("\n")

            msg = "Error appeared while assembling the test case:\n"
            for line in error_msg.split("\n"):
                line = line.removeprefix(asm_file + ":")
                line_num_str = re.search(r"(\d+):", line)
                if not line_num_str:
                    msg += line
                else:
                    parsed = lines[int(line_num_str.group(1)) - 1]
                    msg += f"\n  Line {line}\n    (the line was parsed as {parsed})"
            return msg

        try:
            out = run(f"as {asm_file} -o {obj_file}", shell=True, check=True, capture_output=True)
        except CalledProcessError as e:
            error_msg = e.stderr.decode()
            if "Assembler messages:" in error_msg:
                print(pretty_error_msg(error_msg))
            else:
                print(error_msg)
            raise e
        finally:
            pass
            # run(f"rm {patched_asm_file}", shell=True, check=True)

        output = out.stderr.decode()
        if "Assembler messages:" in output:
            print("WARNING: [generator]" + pretty_error_msg(output))

        run(f"cp {obj_file} {bin_file}", shell=True, check=True)
        run(f"strip --remove-section=.note.gnu.property {bin_file}", shell=True, check=True)
        run(f"objcopy {bin_file} -O binary {bin_file}", shell=True, check=True)

    @abc.abstractmethod
    def get_elf_data(self, test_case: TestCase, obj_file: str) -> None:
        pass

    def create_actors(self, test_case: TestCase) -> None:

        def pte_properties_to_mask(properties: dict, type_: int) -> int:
            """
            Converts a dictionary of PTE properties to a bitmask, later used to set the attributes
            of faulty pages in the executor.
            If properties['randomized'] is set to True, each bit has a chance of retaining its
            default value. Otherwise, the mask is created with the exact values from the dictionary.
            """

            bits = self.target_desc.pte_bits if type_ == 0 else self.target_desc.epte_bits

            # calculate the probability of a bit being set to its default value
            probability_of_default = 0.0
            if properties['randomized']:
                count_non_default = 0
                for bit_name in bits:
                    if bits[bit_name][1] != properties[bit_name]:
                        count_non_default += 1
                probability_of_default = count_non_default / len(properties)

            # create the mask
            mask = 0
            for bit_name in bits:
                bit_offset, default_value = bits[bit_name]

                # transform non_executable to executable
                if bit_name == "non_executable":
                    p_value = not properties["executable"]
                else:
                    p_value = properties[bit_name]

                if random.random() < probability_of_default:
                    p_value = default_value

                bit_value = 1 if p_value else 0
                mask |= bit_value << bit_offset
            return mask

        for name, desc in CONF._actors.items():
            # determine the actor mode of execution
            if desc['mode'] == "host":
                mode = ActorMode.HOST
            elif desc['mode'] == "guest":
                mode = ActorMode.GUEST
            else:
                assert False, f"Invalid actor mode: {desc['mode']}"

            if desc['privilege_level'] == "kernel":
                pl = ActorPL.KERNEL
            elif desc['privilege_level'] == "user":
                pl = ActorPL.USER
            else:
                assert False, f"Invalid actor privilege_level: {desc['privilege_level']}"

            # create the actor
            if name == "main":
                actor = test_case.actors["main"]
            else:
                id_ = 0  # will be assigned later by the ELF parser
                actor = Actor(mode, pl, id_, name)

            # create a PTE mask to be assigned to the faulty area of actors' sandboxes
            actor.data_properties = pte_properties_to_mask(desc["data_properties"], 0)
            if actor.mode == ActorMode.GUEST:
                actor.data_ept_properties = pte_properties_to_mask(desc["data_ept_properties"], 1)

            # assign observer properties (used by non-interference contracts)
            actor.observer = desc['observer']

            # check for duplicates (this should never be possible, but just in case)
            assert name not in test_case.actors or test_case.actors[name] == actor, "Duplicate actr"

            # add the actor to the test case
            test_case.actors[name] = actor

    @abc.abstractmethod
    def generate_function(self, name: str, owner: Actor, parent: TestCase) -> Function:
        pass

    @abc.abstractmethod
    def generate_instruction(self, spec: InstructionSpec) -> Instruction:
        pass

    def generate_operand_revizor(self, spec: OperandSpec, parent: Instruction) -> Operand:
        generators = {
            OT.REG: self.generate_reg_operand,
            OT.MEM: self.generate_mem_operand,
            OT.IMM: self.generate_imm_operand_revizor,
            OT.LABEL: self.generate_label_operand,
            OT.AGEN: self.generate_agen_operand,
            OT.FLAGS: self.generate_flags_operand,
            OT.COND: self.generate_cond_operand,
        }
        return generators[spec.type](spec, parent)

    def generate_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        generators = {
            OT.REG: self.generate_reg_operand,
            OT.MEM: self.generate_mem_operand,
            OT.IMM: self.generate_imm_operand,
            OT.LABEL: self.generate_label_operand,
            OT.AGEN: self.generate_agen_operand,
            OT.FLAGS: self.generate_flags_operand,
            OT.COND: self.generate_cond_operand,
        }
        return generators[spec.type](spec, parent)

    @abc.abstractmethod
    def generate_reg_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_mem_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_imm_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_label_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_agen_operand(self, _: OperandSpec, __: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_flags_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_cond_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def expand_template(self, test_case: TestCase) -> None:
        pass

    @abc.abstractmethod
    def add_terminators_in_function(self, func: Function):
        pass

    @abc.abstractmethod
    def add_instructions_in_function(self, func: Function, size: int):
        pass

    @abc.abstractmethod
    def add_required_symbols(self, test_case: TestCase):
        pass


# ==================================================================================================
# ISA-independent Generators
# ==================================================================================================
class RandomGenerator(ConfigurableGenerator, abc.ABC):
    """
    Implements an ISA-independent logic of random test case generation.
    Subclasses are responsible for the ISA-specific parts.
    """

    def __init__(self, instruction_set: InstructionSet, seed: int):
        super().__init__(instruction_set, seed)
        #print("---------------- RandomGenerator  init----------------")
        uncond_name = self.get_unconditional_jump_instruction().name.lower()
        self.cond_branches = \
            [i for i in self.control_flow_instructions if i.name.lower() != uncond_name]

    def generate_function(self, label: str, owner: Actor, parent: TestCase): 
        """ Generates a random DAG of basic blocks within a function """
        func = Function(label, owner)

        # Define the maximum allowed number of successors for any BB
        if self.instruction_set.has_conditional_branch:
            max_successors = CONF.max_successors_per_bb if CONF.max_successors_per_bb < 2 else 2
            min_successors = CONF.min_successors_per_bb if CONF.min_successors_per_bb < 2 else 2
            assert min_successors <= max_successors, "min_successors_per_bb > max_successors_per_bb"
        else:
            max_successors = 1
            min_successors = 1

        # Create basic blocks
        if CONF.min_bb_per_function == CONF.max_bb_per_function:
            node_count = CONF.min_bb_per_function
        else:
            node_count = random.randint(CONF.min_bb_per_function, CONF.max_bb_per_function)
        func_name = label.removeprefix(".function_")
        nodes = [BasicBlock(f".bb_{func_name}.{i}") for i in range(node_count)]

        # Connect BBs into a graph
        for i in range(node_count):
            current_bb = nodes[i]

            # the last node has only one successor - exit
            if i == node_count - 1:
                current_bb.successors = [func.exit]
                break

            # the rest of the node have a random number of successors
            successor_count = random.randint(min_successors, max_successors)
            if successor_count + i > node_count:
                # the number is adjusted to the position when close to the end
                successor_count = node_count - i

            # one of the targets (the first successor) is always the next node - to avoid dead code
            current_bb.successors.append(nodes[i + 1])

            # all other successors are random, selected from next nodes
            options = nodes[i + 2:]
            options.append(func.exit)
            for j in range(1, successor_count):
                target = random.choice(options)
                options.remove(target)
                current_bb.successors.append(target)

        # Function returns are not yet supported
        # hence all functions end with an unconditional jump to the exit
        func.exit.terminators = [
            self.get_unconditional_jump_instruction().add_op(LabelOperand(parent.exit.name))
        ]

        # Finalize the function
        func.extend(nodes)
        return func
    
    def generate_function_for_v2(self, label: str, owner: Actor, parent: TestCase):
        """ 基本块无需通过条件跳转和非条件跳转来链接，用于v2测试用例生成 """
        func = Function(label, owner)

        # 设定基本块的后继者的数量
        if self.instruction_set.has_conditional_branch:
            max_successors = CONF.max_successors_per_bb if CONF.max_successors_per_bb < 2 else 2
            min_successors = CONF.min_successors_per_bb if CONF.min_successors_per_bb < 2 else 2
            assert min_successors <= max_successors, "min_successors_per_bb > max_successors_per_bb"
        else:
            max_successors = 1
            min_successors = 1

        # Create basic blocks
        if CONF.min_bb_per_function == CONF.max_bb_per_function:
            node_count = CONF.min_bb_per_function
        else:
            node_count = random.randint(CONF.min_bb_per_function, CONF.max_bb_per_function)
        func_name = label.removeprefix(".function_")
        nodes = [BasicBlock(f".bb_{func_name}.{i}") for i in range(node_count)]

        # 将基本块添加进function的列表中
        for i in range(node_count):
            current_bb = nodes[i]

            # the last node has only one successor - exit
            if i == node_count - 1:
                current_bb.successors = [func.exit]
                break

            # 对于其余基本块的后继暂不处理

        # Function returns are not yet supported
        # hence all functions end with an unconditional jump to the exit
        func.exit.terminators = [
            self.get_unconditional_jump_instruction().add_op(LabelOperand(parent.exit.name))
        ]

        # Finalize the function
        func.extend(nodes)
        return func

    def generate_function_without_exitbb(self, label: str, owner: Actor, parent: TestCase): 
        """ 移除每个function指向exit_bb的非条件跳转, 用于v5测试用例生成 """
        func = Function(label, owner)

        # Define the maximum allowed number of successors for any BB
        if self.instruction_set.has_conditional_branch:
            max_successors = CONF.max_successors_per_bb if CONF.max_successors_per_bb < 2 else 2
            min_successors = CONF.min_successors_per_bb if CONF.min_successors_per_bb < 2 else 2
            assert min_successors <= max_successors, "min_successors_per_bb > max_successors_per_bb"
        else:
            max_successors = 1
            min_successors = 1

        # Create basic blocks
        if CONF.min_bb_per_function == CONF.max_bb_per_function:
            node_count = CONF.min_bb_per_function
        else:
            node_count = random.randint(CONF.min_bb_per_function, CONF.max_bb_per_function)
        func_name = label.removeprefix(".function_")
        nodes = [BasicBlock(f".bb_{func_name}.{i}") for i in range(node_count)]

        # Connect BBs into a graph
        for i in range(node_count):
            current_bb = nodes[i]

            # the last node has only one successor - exit
            if i == node_count - 1:
                current_bb.successors = [func.exit]
                break

            # the rest of the node have a random number of successors
            successor_count = random.randint(min_successors, max_successors)
            if successor_count + i > node_count:
                # the number is adjusted to the position when close to the end
                successor_count = node_count - i

            # one of the targets (the first successor) is always the next node - to avoid dead code
            current_bb.successors.append(nodes[i + 1])

            # all other successors are random, selected from next nodes
            options = nodes[i + 2:]
            options.append(func.exit)
            for j in range(1, successor_count):
                target = random.choice(options)
                options.remove(target)
                current_bb.successors.append(target)

        # Finalize the function
        func.extend(nodes)
        return func


    def generate_function_for_phase(self, label: str, owner: Actor, parent: TestCase):
        """ Generates a random DAG of basic blocks within a function for create_phased_test_case """
        func = Function(label, owner)

        # Define the maximum allowed number of successors for any BB
        if self.instruction_set.has_conditional_branch:
            max_successors = CONF.max_successors_per_bb if CONF.max_successors_per_bb < 2 else 2
            min_successors = CONF.min_successors_per_bb if CONF.min_successors_per_bb < 2 else 2
            assert min_successors <= max_successors, "min_successors_per_bb > max_successors_per_bb"
        else:
            max_successors = 1
            min_successors = 1

        # Create basic blocks
        node_count = 3#一个训练块，一个瞬态块，一个fallback_bb
        func_name = label.removeprefix(".function_")
        nodes = [BasicBlock(f".bb_{func_name}.{i}") for i in range(node_count)]
        
        # Connect BBs into a graph
        for i in range(node_count):
            current_bb = nodes[i]

            # the last node has only one successor - exit
            if i == node_count - 1:
                current_bb.successors = [func.exit]
                break

            # 第一个bb有两个后继
            if i == 0:
                successor_count = 2
            elif i == 1:
                successor_count = random.randint(1, 2)
                if successor_count + i > node_count:
                    # the number is adjusted to the position when close to the end
                    successor_count = node_count - i
           

            # one of the targets (the first successor) is always the next node - to avoid dead code
            current_bb.successors.append(nodes[i + 1])

            # 先给第一个基本块指定后继分别为第2和3个基本块
            if i == 0:
                current_bb.successors.append(nodes[i + 2])
                continue
            
            # all other successors are random, selected from next nodes
            options = nodes[i + 2:]
            options.append(func.exit)
            for j in range(1, successor_count):
                target = random.choice(options)
                options.remove(target)
                current_bb.successors.append(target)

        # Function returns are not yet supported
        # hence all functions end with an unconditional jump to the exit
        func.exit.terminators = [
            self.get_unconditional_jump_instruction().add_op(LabelOperand(parent.exit.name))
        ]

        # Finalize the function
        func.extend(nodes)
        return func

    def generate_instruction_revizor(self, spec: InstructionSpec) -> Instruction:
        '''
        with open("instruction_spec_log.txt", "a") as spec_file:
            spec.dump_to_file(spec_file)
        '''
        # fill up with random operands, following the spec
        inst = Instruction.from_spec(spec)

        # generate explicit operands
        for operand_spec in spec.operands:
            operand = self.generate_operand_revizor(operand_spec, inst)
            inst.operands.append(operand)

        # generate implicit operands
        for operand_spec in spec.implicit_operands:
            operand = self.generate_operand_revizor(operand_spec, inst)
            inst.implicit_operands.append(operand)
        '''
        with open("instruction_instance_log.txt", "a") as inst_file:
            inst.dump_to_file(inst_file)
        '''
        return inst

    def generate_instruction(self, spec: InstructionSpec) -> Instruction:
        '''
        with open("instruction_spec_log.txt", "a") as spec_file:
            spec.dump_to_file(spec_file)
        '''
        # fill up with random operands, following the spec
        inst = Instruction.from_spec(spec)

        # generate explicit operands
        for operand_spec in spec.operands:
            operand = self.generate_operand(operand_spec, inst)
            inst.operands.append(operand)

        # generate implicit operands
        for operand_spec in spec.implicit_operands:
            operand = self.generate_operand(operand_spec, inst)
            inst.implicit_operands.append(operand)
        '''
        with open("instruction_instance_log.txt", "a") as inst_file:
            inst.dump_to_file(inst_file)
        '''
        return inst

    def generate_reg_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        reg_type = spec.values[0]
        if reg_type == 'gpr':  # deprecated?
            choices = self.target_desc.registers[spec.width]
        elif reg_type == "simd":  # deprecated?
            choices = self.target_desc.simd_registers[spec.width]
        else:
            choices = spec.values

        reg = random.choice(choices)
        return RegisterOperand(reg, spec.width, spec.src, spec.dest)

    def generate_mem_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        if spec.values:
            address_reg = random.choice(spec.values)
        else:
            address_reg = random.choice(self.target_desc.registers[64])
        return MemoryOperand(address_reg, spec.width, spec.src, spec.dest)
    
    def generate_imm_operand_revizor(self, spec: OperandSpec, _: Instruction) -> Operand:
        # generate bitmask
        if spec.values and spec.values[0] == "bitmask":
            # FIXME: this implementation always returns the same bitmask
            # make it random
            value = str(pow(2, spec.width) - 2)
            return ImmediateOperand(value, spec.width)

        # generate from a predefined range
        if spec.values:
            assert "[" in spec.values[0], spec.values
            range_ = spec.values[0][1:-1].split("-")
            if range_[0] == "":
                range_ = range_[1:]
                range_[0] = "-" + range_[0]
            assert len(range_) == 2
            value = str(random.randint(int(range_[0]), int(range_[1])))
            ImmediateOperand(value, spec.width)

        # generate from width
        if spec.signed:
            range_min = pow(2, spec.width - 1) * -1
            range_max = pow(2, spec.width - 1) - 1
        else:
            range_min = 0
            range_max = pow(2, spec.width) - 1
        value = str(random.randint(range_min, range_max))
        return ImmediateOperand(value, spec.width)


    def generate_imm_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        # generate bitmask
        if spec.values and spec.values[0] == "bitmask":
            print("------- generate_imm_operand  bitmask -------")
            # FIXME: this implementation always returns the same bitmask
            # make it random
            value = str(pow(2, spec.width) - 2)
            return ImmediateOperand(value, spec.width)

        # generate from a predefined range
        if spec.values:
            #print("------- generate_imm_operand  range -------")
            assert "[" in spec.values[0], spec.values
            range_ = spec.values[0][1:-1].split("-")
            if range_[0] == "":
                range_ = range_[1:]
                range_[0] = "-" + range_[0]
            assert len(range_) == 2
            value = str(random.randint(int(range_[0]), int(range_[1])))
            return ImmediateOperand(value, spec.width)

        # generate from width
        if spec.signed:
            #print("------- generate_imm_operand  signed -------")
            range_min = pow(2, spec.width - 1) * -1
            range_max = pow(2, spec.width - 1) - 1
        else:
            #print("------- generate_imm_operand  unsigned -------") 
            range_min = 0
            range_max = pow(2, spec.width) - 1
        
        # 以50的概率生成2的幂次的立即数
        if random.random() < 0.5:
            possible_exponents = []
            if not spec.signed:
                # 无符号：仅生成正数
                max_exp = int(math.log2(range_max)) if range_max > 0 else 0
                exp = random.randint(0, max_exp)
                val = 2 ** exp
            else:
                # 有符号：可能取负
                max_exp = int(math.log2(abs(range_max))) if range_max > 0 else 0
                exp = random.randint(0, max_exp)
                val = 2 ** exp
                if random.random() < 0.5:
                    val = -val

             # 修正越界：强制落在 [range_min, range_max] 内
            val = max(range_min, min(val, range_max))
            value = str(val)
            #print(f"------- generate_imm_operand  power_of_two ({value}) -------")
        else:
            value = str(random.randint(range_min, range_max))

        return ImmediateOperand(value, spec.width)

    def generate_label_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        return LabelOperand("")  # the actual label will be set in add_terminators_in_function

    def generate_agen_operand(self, spec: OperandSpec, __: Instruction) -> Operand:
        n_operands = random.randint(1, 3)
        reg1 = random.choice(self.target_desc.registers[64])
        if n_operands == 1:
            return AgenOperand(reg1, spec.width)

        reg2 = random.choice(self.target_desc.registers[64])
        if n_operands == 2:
            return AgenOperand(reg1 + " + " + reg2, spec.width)

        imm = str(random.randint(0, pow(2, 16) - 1))
        return AgenOperand(reg1 + " + " + reg2 + " + " + imm, spec.width)

    def generate_flags_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        cond_op = parent.get_cond_operand()
        if not cond_op:
            return FlagsOperand(spec.values)

        flag_values = self.target_desc.branch_conditions[cond_op.value]
        if not spec.values:
            return FlagsOperand(flag_values)

        # combine implicit flags with the condition
        merged_flags = []
        for flag_pair in zip(flag_values, spec.values):
            if "undef" in flag_pair:
                merged_flags.append("undef")
            elif "r/w" in flag_pair:
                merged_flags.append("r/w")
            elif "w" in flag_pair:
                if "r" in flag_pair:
                    merged_flags.append("r/w")
                else:
                    merged_flags.append("w")
            elif "cw" in flag_pair:
                if "r" in flag_pair:
                    merged_flags.append("r/cw")
                else:
                    merged_flags.append("cw")
            elif "r" in flag_pair:
                merged_flags.append("r")
            else:
                merged_flags.append("")
        return FlagsOperand(merged_flags)

    def generate_cond_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        cond = random.choice(list(self.target_desc.branch_conditions))
        return CondOperand(cond)

    def expand_template(self, test_case: TestCase):
        instr_to_expand: List[Tuple[Instruction, BasicBlock, str]] = []
        for func in test_case.functions:
            for bb in func:
                for instr in bb:
                    if instr.name == "macro" and instr.operands[0].value == ".random_instructions":
                        instr_to_expand.append((instr, bb, func.owner.name))

        for inst, bb, a_name in instr_to_expand:
            operands = inst.operands[1].value.split(".")
            assert len(operands) >= 3 and len(operands) <= 5
            n_instr = int(operands[1])
            n_mem = int(operands[2])
            predecessor = inst.previous

            # determine the instruction set for this actor
            blocklist = CONF._actors[a_name]["instruction_blocklist"]
            non_memory_access_instructions = \
                [i for i in self.non_memory_access_instructions if i.name not in blocklist]
            store_instructions = [i for i in self.store_instructions if i.name not in blocklist]
            load_instruction = [i for i in self.load_instruction if i.name not in blocklist]

            # replace the macro with random instructions
            bb.delete(inst)
            for _ in range(n_instr):
                spec = self._pick_random_instruction_spec(non_memory_access_instructions,
                                                          store_instructions, load_instruction,
                                                          n_mem / n_instr)
                # generate_instruction是概率生成2的幂次优化后的版本
                inst = self.generate_instruction(spec)
                if predecessor:
                    bb.insert_after(predecessor, inst)
                else:
                    bb.insert_before(bb.get_first(), inst)

    def add_terminators_in_function(self, func: Function):

        def add_fallthrough(bb: BasicBlock, destination: BasicBlock):
            # create an unconditional branch and add it
            terminator = self.get_unconditional_jump_instruction()
            terminator.operands = [LabelOperand(destination.name)]
            bb.terminators.append(terminator)

        for bb in func:
            if len(bb.successors) == 0:
                # Return instruction
                continue

            elif len(bb.successors) == 1:
                # Unconditional branch
                dest = bb.successors[0]
                if dest == func.exit:
                    # DON'T insert a branch to the exit
                    # the last basic block always falls through implicitly
                    continue
                add_fallthrough(bb, dest)

            elif len(bb.successors) == 2:
                # Conditional branch
                spec = random.choice(self.cond_branches)
                # generate_instruction是概率生成2的幂次优化后的版本
                # 使用Revizor版本要使用generate_instruction_revizor
                terminator = self.generate_instruction(spec)
                label = terminator.get_label_operand()
                assert label
                label.value = bb.successors[0].name
                bb.terminators.append(terminator)

                add_fallthrough(bb, bb.successors[1])
            else:
                # Indirect jump
                raise NotSupportedException()

    def add_instructions_in_function(self, func: Function):
        # evenly fill all BBs with random instructions
        bb_list = func[:]
        for _ in range(0, CONF.program_size):
            bb = random.choice(bb_list)
            spec, is_store = self._pick_random_instruction_spec(self.non_memory_access_instructions,
                                                      self.store_instructions,
                                                      self.load_instruction,
                                                      CONF.avg_mem_accesses / CONF.program_size)
            #breakpoint()
            # generate_instruction是概率生成2的幂次优化后的版本
            # 使用Revizor版本要使用generate_instruction_revizor
            inst = self.generate_instruction(spec)
            bb.insert_after(bb.get_last(), inst)
    
    def add_instructions_in_v5_function(self, func: Function, size: int):
        bb_list = func[:]
        for bb in bb_list:
            for _ in range(0, size):
                spec, is_store = self._pick_random_instruction_spec(self.non_memory_access_instructions,
                                                          self.store_instructions,
                                                          self.load_instruction,
                                                          CONF.avg_mem_accesses / CONF.program_size)
                inst = self.generate_instruction(spec)
                bb.insert_after(bb.get_last(), inst)

    def add_instructions_in_v2_function(self, func: Function):
        size_list = [0.5, 0.25, 0.25]  # 分配给3个基本块的指令数占比
        bb_list = func[:]
        for i, bb in enumerate(bb_list):
            size = int(CONF.program_size * size_list[i])
            for _ in range(0, size):
                spec, is_store = self._pick_random_instruction_spec(self.non_memory_access_instructions,
                                                          self.store_instructions,
                                                          self.load_instruction,
                                                          CONF.avg_mem_accesses / CONF.program_size)
                inst = self.generate_instruction(spec)
                bb.insert_after(bb.get_last(), inst)


    def _pick_random_instruction_spec(self,
                                      non_memory_access_instructions: List,
                                      store_instructions: List,
                                      load_instructions: List,
                                      memory_access_probability: float = 0.0,
                                      is_store: bool = False ) -> Tuple[InstructionSpec, bool]:
        # ensure the requested avg. number of mem. accesses
        search_for_memory_access = random.random() < memory_access_probability
        if not search_for_memory_access:
            return random.choice(non_memory_access_instructions), False

        if store_instructions:
            search_for_store = random.random() < 0.5  # 50% probability of stores
        else:
            search_for_store = False

        if search_for_store:
            spec = random.choice(store_instructions)
            return spec, True

        spec = random.choice(load_instructions)
        return spec, False
    
    def add_instructions_in_v4_function(self, func: Function):
        '''插入store之后有概率插入地址相近的load'''
        # evenly fill all BBs with random instructions
        bb_list = func[:]
        is_store = False
        load_inserted_once = False # 记录本函数是否已经插入过一次load以及lea依赖链（一个用例最多一次）

        for _ in range(0, CONF.program_size):
            bb = random.choice(bb_list)
            spec, is_store = self._pick_random_instruction_spec(self.non_memory_access_instructions,
                                                      self.store_instructions,
                                                      self.load_instruction,
                                                      CONF.avg_mem_accesses / CONF.program_size,
                                                      is_store)
            #breakpoint()
            inst = self.generate_instruction(spec)
            bb.insert_after(bb.get_last(), inst)
            
            #print(f"Inserted instruction: {inst.__str__()}")
            # 如果刚插入的是store指令,则有50%的概率插入地址相近的load指令
            if is_store and (not load_inserted_once):
                # 以60%的概率插入地址相近的load
                if random.random() < 0.6:
                    print(f"Generated store instruction: {inst.__str__()}")
                    # load_spec = random.choice(self.load_instruction)
                    # load_inst = self.generate_instruction(load_spec)
                    # load指令选取mov reg, [mem]
                    load_inst = Instruction(
                        name="mov",
                        is_instrumentation=False,
                        category="BASE-DATAXFER",
                        control_flow=False
                    )
                    rdx_op = RegisterOperand("rdx", src=False, dest=True, width=64)
                    load_inst.add_op(rdx_op)

                    store_mem_op = None
                    try:
                        if len(inst.operands) > 0 and isinstance(inst.operands[0], MemoryOperand):
                            store_mem_op = inst.operands[0]
                        else:
                            for op in inst.operands:
                                if isinstance(op, MemoryOperand):
                                    store_mem_op = op
                                    break
                    except Exception as e:
                        store_mem_op = None
                        #print(f"Warning: error while inspecting store operands: {e}")

                    # 深拷贝以避免两个指令共享同一对象
                    store_mem_op_copy = copy.deepcopy(store_mem_op)
                    load_inst.add_op(store_mem_op_copy)
                    self.fix_operand_width(load_inst)
                    bb.insert_after(bb.get_last(), load_inst)
                    load_inserted_once = True

                    # 在插入的load之后再插入一条load，将信息带到缓存中
                    # mov rdx, qword ptr [r14 + rdx]
                    load_inst_2 = Instruction(
                        name="mov",
                        is_instrumentation=False,
                        category="BASE-DATAXFER",
                        control_flow=False
                    )
                    load_inst_2.add_op(rdx_op)
                    mem_rdx_op = MemoryOperand("rdx", width=64, src=True, dest=False)
                    load_inst_2.add_op(mem_rdx_op)
                    #为了进行第二个消融实验注释掉
                    bb.insert_after(bb.get_last(), load_inst_2)


                    #replaced = False
                    if store_mem_op_copy is not None:
                        # 深拷贝以避免两个指令共享同一对象
                        #store_mem_op_copy = copy.deepcopy(store_mem_op)

                        # 在store之前加入lea依赖链
                        reg_operand_value = self.extract_register_from_mem_operand(store_mem_op_copy)
                        if reg_operand_value is not None:
                            print(f"Extracted register from store memory operand: {reg_operand_value}")
                            # 构造lea指令
                            lea_inst = Instruction(
                                name="lea",
                                is_instrumentation=False,
                                category="BASE-MISC",
                                control_flow=False
                            )
                            lea_reg_op = RegisterOperand(
                                value=reg_operand_value,
                                width=64,
                                src=False,
                                dest=True
                            )
                            lea_inst.add_op(lea_reg_op)
                            # 生成lea指令的agen操作数
                            addr_expr = f"[{reg_operand_value} + {2 * random.randint(1, 4)}]"
                            addr_expr_1 = f"[{reg_operand_value} - {2 * random.randint(1, 4)}]"
                            lea_agen_op = AgenOperand(addr_expr, 64)
                            lea_inst.add_op(lea_agen_op)
                            lea_inst_1 = Instruction(
                                name="lea",
                                is_instrumentation=False,
                                category="BASE-MISC",
                                control_flow=False
                            )
                            lea_inst_1.add_op(lea_reg_op)
                            lea_agen_op_1 = AgenOperand(addr_expr_1, 64)
                            lea_inst_1.add_op(lea_agen_op_1)

                            for i in range(13):
                                # 26条lea比较稳定
                                lea_inst_copy = copy.deepcopy(lea_inst)
                                lea_inst_1_copy = copy.deepcopy(lea_inst_1)
                                #为了进行第二个消融实验注释掉
                                bb.insert_before(inst, lea_inst_copy)
                                bb.insert_before(inst, lea_inst_1_copy)

                            print(f"Inserted lea instructions: {lea_inst.__str__()} and {lea_inst_1.__str__()}")

                        #self.fix_operand_width(load_inst)
                        #bb.insert_after(bb.get_last(), load_inst)
            
                        #print(f"Inserted load instruction: {load_inst.__str__()}")
                        #load_inserted_once = True

                    is_store = False
                

    def extract_register_from_mem_operand(self, mem_op: MemoryOperand) -> str | None:
        """
        从内存操作数（如 "[rbx + rax + 4]"）中提取第一个寄存器名。
        例如返回 "rbx"；若未找到寄存器则返回 None。
        """
        match = re.search(r'\b[rR][a-z]{2}\b', mem_op.value)
        return match.group(0).lower() if match else None


    def fix_operand_width(self, inst: Instruction):
        for op in inst.operands:
            if isinstance(op, MemoryOperand):
                reg = next((r for r in inst.operands if isinstance(r, RegisterOperand)), None)
                if reg is None:
                    continue

                # 特殊指令：bt 不支持 byte 操作数
                if inst.name == "bt":
                    if reg.width >= 64:
                        op.ptr = 'qword ptr'
                        op.width = 64
                    elif reg.width >= 32:
                        op.ptr = 'dword ptr'
                        op.width = 32
                    else:
                        op.ptr = 'word ptr'
                        op.width = 16
                    continue

                # movsx/movzx 特判，防止不被支持的组合
                if inst.name in ["movsx", "movzx"]:
                    if reg.width == 64:
                        op.ptr = 'word ptr'
                        op.width = 16
                    elif reg.width == 32:
                        op.ptr = 'word ptr'
                        op.width = 16
                    elif reg.width == 16:
                        op.ptr = 'byte ptr'
                        op.width = 8
                    continue

                # 一般情况
                if reg.width == 64:
                    op.ptr = 'qword ptr'
                    op.width = 64
                elif reg.width == 32:
                    op.ptr = 'dword ptr'
                    op.width = 32
                elif reg.width == 16:
                    op.ptr = 'word ptr'
                    op.width = 16
                elif reg.width == 8:
                    op.ptr = 'byte ptr'
                    op.width = 8




    @abc.abstractmethod
    def get_return_instruction(self) -> Instruction:
        pass

    @abc.abstractmethod
    def get_unconditional_jump_instruction(self) -> Instruction:
        pass

    def add_required_symbols(self, test_case: TestCase):
        # add measurement_start and measurement_end symbols
        func_main = test_case.functions[0]
        assert func_main.owner == test_case.actors["main"]

        bb_first = func_main[0]
        instr = Instruction("macro", category="MACRO") \
            .add_op(LabelOperand(".measurement_start")) \
            .add_op(LabelOperand(".noarg"))
        bb_first.insert_before(bb_first.get_first(), instr)

        '''
        bb_last = func_main.exit
        instr = Instruction("macro", category="MACRO") \
            .add_op(LabelOperand(".measurement_end")) \
            .add_op(LabelOperand(".noarg"))
        bb_last.insert_after(bb_last.get_last(), instr)
        '''
        # 注释掉的部分会在第一个function的最后插入measurement_end标记
        # v5有多个function，这里不适用
        func_last = test_case.functions[-1]
        assert func_last.owner == test_case.actors["main"]

        bb_last = func_last.exit
        instr = Instruction("macro", category="MACRO") \
            .add_op(LabelOperand(".measurement_end")) \
            .add_op(LabelOperand(".noarg"))
        bb_last.insert_after(bb_last.get_last(), instr)