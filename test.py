#!/usr/bin/env python
import sys
import os
import re
from bintran import Elf32, Elf32_Rel, Elf32_Sym, Elf32_Shdr
from uuid import uuid4
from ctypes import *

def flatten(elf):
    '''rewrite short "jmp" to near "jmp"'''
    sjs = filter(lambda i: i.mnemonic.startswith('j') and \
            i.op_str[0] != '*' and len(i) == 2, elf.disasm())
    print '  %d short JMPs' % len(sjs)
    elf.flatten()
    return elf

def call_to_jmp(elf):
    '''rewrite "call dest" to "push addr; jmp dest"'''
    syms = elf('.symtab', Elf32_Sym)
    # find symbol index of .text section
    tsndx = next((i for i in range(len(syms)) if syms[i].st_info & 0xf == 3 and syms[i].st_shndx == 1), -1)
    assert tsndx >= 0, 'symbol of .text section is not found'
    calls = filter(lambda i: i.mnemonic == 'call', elf.disasm())
    print '  %d CALLs found' % len(calls)
    calls.reverse()
    for i in calls:
        # insert "push addr"
        elf.insert(i.address, '\x68%s' % string_at(pointer(c_uint(i.address+5+len(i))), 4))
        # add a relent for the return address in "push"
        if not elf('.rel.text'):
            symtab_shndx = (addressof(elf('.symtab')) - addressof(elf.shdrs)) / sizeof(Elf32_Shdr)
            elf.add_section('.rel.text', sh_type=9, sh_info=1, sh_entsize=sizeof(Elf32_Rel), sh_link=symtab_shndx)
        elf.add_entry(elf('.rel.text'), Elf32_Rel(i.address+1, (tsndx<<8)+1), lambda r: r.r_offset)
        # rewrite "call" to "jmp"
        call_offset = elf('.text').sh_offset + i.address + 5
        if elf[call_offset] == '\xe8': # direct "call"
            elf[call_offset] = '\xe9'
        elif elf[call_offset] == '\xff': # indirect "call"
            elf[call_offset+1] = chr(ord(elf[call_offset+1]) + 0x10)
        else:
            assert False, 'what is the call? %s' % str(i)
    return elf

def ret_to_jmp(elf):
    '''rewrite "ret" to "pop %ecx; jmp *%ecx"'''
    rets = [i.address for i in filter(lambda i: i.bytes == '\xc3', elf.disasm())]
    print '  %d RETs found' % len(rets)
    rets.reverse()
    for r in rets:
        elf.insert(r, '\x90'*2)
        elf[elf('.text').sh_offset+r:] = '\x59\xff\xe1'
    return elf

def add_nop(elf):
    '''add "nop" between every two instruction'''
    iaddrs = [i.address for i in elf.disasm()]
    print '  %d insns found' % len(iaddrs)
    iaddrs.reverse()
    for ia in iaddrs:
        elf.insert(ia, '\x90')
    return elf

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print ('usage: test.py [option+option+..] xxx.o\n'
               '  flatten: rewrite all short JMPs to near JMPs\n'
               '  call_to_jmp: rewrite CALL to PUSH and JMP\n'
               '  ret_to_jmp: rewrite RET to POP and JMP\n'
               '  add_nop: add NOP after every instruction')
        sys.exit(0)
    tests = [globals()[t] for t in sys.argv[1].split('+')]
    for objfile in sys.argv[2:]:
        print '%s' % objfile
        with open(objfile, 'rb') as f:
            elf = Elf32(f.read())
        for t in tests:
            elf = t(elf)
        with open(objfile, 'wb') as f:
            f.write(str(elf))
