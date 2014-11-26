#!/usr/bin/env python
import sys
import os
import re
from bintran import Elf32, Elf32_Rel, Elf32_Sym
from uuid import uuid4
from ctypes import *

def call_to_jmp(elf):
    syms = elf('.symtab', Elf32_Sym)
    for ndx in range(len(syms)):
        if syms[ndx].st_info & 0xf == 3 and syms[ndx].st_shndx == 1:
            break # found symbol of STT_SECTION for .text
    else:
        assert False, 'no symbol for .text section'
    calls = filter(lambda i: i.mnemonic == 'call' and i.bytes.startswith('\xe8'), elf.disasm())
    print '  %d CALLs found' % len(calls)
    calls.reverse()
    for i in calls:
        r = Elf32_Rel(i.address+1, (ndx<<8)+1)
        try:
            elf.insert(i.address, '\x68%s' % string_at(pointer(c_uint(i.address+10)), 4))
            elf.addent(elf('.rel.text'), r, lambda r: r.r_offset)
            elf[elf('.text').sh_offset+i.address+5] = '\xe9'
        except AssertionError, ae:
            print ' ', ae
            continue
    return elf

def protect_switch(elf):
    '''add checks before jmp *table(,%reg,4)'''
    syms = elf('.symtab', Elf32_Sym)
    insns = elf.disasm()
    insns.reverse()
    for i in insns:
        if i.mnemonic != 'jmp':
            continue
        r = re.search(r'\*(.*)\(,%(.*),4\)', i.op_str)
        if not r:
            continue
        print '  %x: %s %s' % (i.address, i.mnemonic, i.op_str)
        addend, reg = int(r.group(1), 16), r.group(2)
        assert addend == 0, 'more than two switchs?'
        # find the relent of table base in the instruction
        for r in elf('.rel.text', Elf32_Rel):
            if r.r_offset == i.address + 3:
                break
        else:
            assert False, 'relent for switch-case jump table is not found'
        # find the symbol associated with the relent
        assert r.r_info & 0xff == 1, 'not an R_386_32 relent?'
        s = syms[r.r_info>>8]
        assert s.st_info & 0xf == 3, 'not a section symbol?'
        # find SHT_REL section for jump table section (e.g., .rodata)
        for sh in elf.shdrs:
            if sh.sh_type == 9 and sh.sh_info == s.st_shndx:
                break
        else:
            assert False, 'SHT_REL for jump table section not found'
        # count the number of jump table entries
        rels = (sh.sh_size/sizeof(Elf32_Rel) * Elf32_Rel).from_buffer(elf.binary, sh.sh_offset)
        count = 0
        marker = addend
        for r in rels:
            if r.r_offset < marker:
                continue
            if r.r_offset == marker:
                count += 1
                marker += 4
            else:
                break
        # generate instrumentation
        nasm = 'bits 32\ncmp %s,%d\nspin: jae spin' % (reg, count)
        tmpfile = '.%s' % uuid4()
        with open(tmpfile, 'w') as f:
            f.write(nasm)
        os.system('nasm %s -o %s.o' % (tmpfile, tmpfile))
        with open('%s.o' % tmpfile, 'rb') as f:
            payload = f.read()
        os.unlink(tmpfile)
        os.unlink('%s.o' % tmpfile)
        # apply instrumentation
        elf.insert(i.address, payload)
    return elf

def ret_to_jmp(elf):
    '''rewrite "ret" with "add $4, %esp; jmp *-4(%esp);'''
    rets = filter(None, [i.address if i.bytes == '\xc3' else 0 for i in elf.disasm()])
    print '  %d RETs found' % len(rets)
    rets.reverse()
    for r in rets:
        try:
            elf.insert(r, '\x90'*6)
            elf[elf('.text').sh_offset+r:] = '\x83\xc4\x04\xff\x64\x24\xfc'
        except AssertionError, ae:
            print ' ', ae
            continue
    return elf

def add_nop(elf):
    '''add "nop" between every two instruction'''
    iaddrs = [i.address for i in elf.disasm()]
    print '  %d insns found' % len(iaddrs)
    iaddrs.reverse()
    for ia in iaddrs:
        try:
            elf.insert(ia, '\x90')
        except AssertionError, ae:
            print ' ', ae
            break
    return elf

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print ('usage: test.py [option] xxx.o\n'
               '  opt: protect_switch, ret_to_jmp, add_nop')
        sys.exit(0)
    test = globals().get(sys.argv[1])
    assert test, 'unrecognized test %s' % sys.argv[1]
    for objfile in sys.argv[2:]:
        print '%s' % objfile
        with open(objfile, 'rb') as f:
            binary = f.read()
        elf = test(Elf32(binary))
        with open(objfile, 'wb') as f:
            f.write(str(elf))
