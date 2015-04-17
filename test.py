#!/usr/bin/env python
import sys
import os
import re
import struct
from bintran import Elf32, Elf32_Rel, Elf32_Sym, Elf32_Shdr
from ctypes import *

def flatten(elf):
    '''rewrite short JMP to near JMP'''
    sjs = filter(lambda i: i.mnemonic.startswith('j') and \
            i.op_str[0] != '*' and len(i) == 2, elf.disasm())
    print '  %d short JMPs' % len(sjs)
    elf.flatten()
    return elf

def call_to_jmp(elf):
    '''rewrite CALL to PUSH + JMP'''
    calls = filter(lambda i: i.mnemonic == 'call', elf.disasm())
    print '  %d CALLs found' % len(calls)
    if not calls:
        return elf
    # prepend PUSH
    elf.insert(*[(calls[i].address, '\x68%s' % \
            struct.pack('i', 5*(i+1)+calls[i].address+len(calls[i])))
            for i in range(len(calls))])
    # update CALLs
    calls = filter(lambda i: i.mnemonic == 'call', elf.disasm())
    # rewrite CALL to JMP
    # see http://pdos.csail.mit.edu/6.828/2012/readings/i386/CALL.htm
    # and http://pdos.csail.mit.edu/6.828/2012/readings/i386/JMP.htm
    # for conversion rules
    for c in calls:
        off = elf('.text').sh_offset + c.address
        if elf[off] == '\xe8': # direct CALL
            elf[off] = '\xe9'
        else: # indirect CALL
            assert elf[off] == '\xff', 'what is the call? %s' % str(c)
            elf[off+1] = chr(ord(elf[off+1])+0x10)
    # create .rel.text if not exists
    tshndx = (addressof(elf('.text')) - addressof(elf.shdrs)) / sizeof(Elf32_Shdr)
    if not elf('.rel.text'):
        stshndx = (addressof(elf('.symtab')) - addressof(elf.shdrs)) / sizeof(Elf32_Shdr)
        elf.new('.rel.text', sh_type=9, sh_info=tshndx, \
                sh_entsize=sizeof(Elf32_Rel), sh_link=stshndx)
    # get the index of symbol representing .text section
    syms = elf('.symtab', Elf32_Sym)
    sndx = next(i for i in range(len(syms)) if \
            syms[i].st_info & 0xf == 3 and syms[i].st_shndx == tshndx)
    # prepare relocations
    rels = [Elf32_Rel(c.address-4, (sndx<<8)+1) for c in calls]
    elf.append(elf('.rel.text'), (len(rels)*Elf32_Rel)(*rels))
    return elf

def ret_to_jmp(elf):
    '''rewrite RET to POP + JMP'''
    rets = [i.address for i in filter(lambda i: i.bytes == '\xc3', elf.disasm())]
    print '  %d RETs found' % len(rets)
    for r in rets:
        elf[elf('.text').sh_offset+r] = '\xe1'
    elf.insert(*[(r, '\x59\xff') for r in rets])
    return elf

def add_nop(elf):
    '''add NOP between every two instruction'''
    iaddrs = [i.address for i in elf.disasm()]
    print '  %d insns found' % len(iaddrs)
    elf.insert(*[(ia, '\x90') for ia in iaddrs])
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
            f.write(elf)
