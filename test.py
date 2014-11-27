#!/usr/bin/env python
import sys
import os
import re
from bintran import Elf32, Elf32_Rel, Elf32_Sym, Elf32_Shdr
from uuid import uuid4
from ctypes import *

def short_jmp_to_near(elf):
    '''convert all short JMPs to near JMPs'''
    new_iaddr = lambda addr: addr + sum([0 if j.address >= addr else \
            3 if j.bytes.startswith('\xeb') else 4 \
            for j in sjs])
    new_insn = lambda i, new_off: ('\xe9' if i.bytes[0] == '\xeb' else \
            ('\x0f%s' % chr(ord(i.bytes[0])+0x10)))\
            + string_at(pointer(c_int(new_off)), 4)
    sjs = filter(lambda i: i.mnemonic.startswith('j') and \
            i.op_str[0] != '*' and \
            len(i.bytes) == 2, elf.disasm())
    print '  %d short JMPs' % len(sjs)
    if not sjs:
        return elf
    assert not filter(lambda i: i.mnemonic in ('jcxz', 'jecxz'), sjs),\
            'JCXZ and JECXZ are unsupported'
    _text = elf('.text')
    syms = elf('.symtab', Elf32_Sym)
    # update .text section
    updts = []
    for i in elf.disasm():
        if i.mnemonic != 'call' and not i.mnemonic.startswith('j'):
            continue # filter out non control transfer instructions
        if i.op_str.startswith('*'):
            continue # filter out indirect control transfers
        opnd_size = 1 if len(i) == 2 else 4
        opnd_text_off = i.address + len(i) - opnd_size
        for r in elf('.rel.text', Elf32_Rel):
            if opnd_text_off == r.r_offset: # skip relocation entries
                break
        else: # a real direct CALL/JMP
            if opnd_size == 4: # a near JMP
                tgt = i.address + len(i) + elf[_text.sh_offset+opnd_text_off, c_int]
                tgt = new_iaddr(tgt)
                iaddr = new_iaddr(i.address)
                new_off = tgt - iaddr - len(i)
                elf[_text.sh_offset+opnd_text_off, c_int] = new_off
            else: # a short JMP
                tgt = i.address + len(i) + elf[_text.sh_offset+opnd_text_off, c_int8]
                tgt = new_iaddr(tgt)
                iaddr = new_iaddr(i.address)
                new_len = 5 if i.bytes.startswith('\xeb') else 6
                new_off = tgt - iaddr - new_len
                updts.append((i, new_off))
    assert len(updts) == len(sjs), 'miss any short JMP?'
    # update relocation entries
    for sh in elf.shdrs:
        if sh.sh_type != 9: # SHT_REL
            continue
        rels = (sh.sh_size/sizeof(Elf32_Rel) * Elf32_Rel).from_buffer(elf.binary, sh.sh_offset)
        for r in rels:
            s = syms[r.r_info>>8]
            if r.r_info & 0xff == 1 and s.st_info & 0xf == 3 and s.st_shndx == 1: # R_386_32 and .text
                addend = elf[elf.shdrs[sh.sh_info].sh_offset+r.r_offset, c_uint]
                elf[elf.shdrs[sh.sh_info].sh_offset+r.r_offset, c_uint] = new_iaddr(addend)
            if sh.sh_info == 1: # update offsets of relocation entries in .text section
                r.r_offset = new_iaddr(r.r_offset)
    # update symbols of .text section
    for s in syms:
        if s.st_shndx != 1: # [1] .text
            continue
        s.st_value = new_iaddr(s.st_value)
        s.st_size = 0 # set it to be unknown
    # update section header table offset
    elf.ehdr.e_shoff += new_iaddr(_text.sh_size) - _text.sh_size
    # update later sections
    for sh in elf.shdrs:
        if sh.sh_offset <= _text.sh_offset:
            continue
        sh.sh_offset += new_iaddr(_text.sh_size) - _text.sh_size
    # update text section header
    _text.sh_size = new_iaddr(_text.sh_size)
    # update binary
    binary = str(elf)
    pieces = []
    for i in range(len(sjs)):
        start = 0 if i == 0 else (_text.sh_offset + sjs[i-1].address + len(sjs[i-1].bytes))
        end = _text.sh_offset + sjs[i].address
        insn = new_insn(*updts[i])
        pieces.append(binary[start:end] + insn)
    pieces.append(binary[_text.sh_offset+sjs[-1].address+len(sjs[-1].bytes):])
    elf.__init__(''.join(pieces))
    return elf

def call_to_jmp(elf):
    '''convert CALL to PUSH and JMP'''
    syms = elf('.symtab', Elf32_Sym)
    for ndx in range(len(syms)):
        if syms[ndx].st_info & 0xf == 3 and syms[ndx].st_shndx == 1:
            break # found symbol of STT_SECTION for .text
    else:
        assert False, 'no symbol for .text section'
    calls = filter(lambda i: i.mnemonic == 'call', elf.disasm())
    print '  %d CALLs found' % len(calls)
    calls.reverse()
    for i in calls:
        r = Elf32_Rel(i.address+1, (ndx<<8)+1)
        try:
            push = '\x68%s' % string_at(pointer(c_uint(i.address+5+len(i.bytes))), 4)
            elf.insert(i.address, push)
            if not elf('.rel.text'):
                elf.add_section('.rel.text', sh_type = 9, sh_info = 1, sh_entsize = sizeof(r),
                        sh_link = (addressof(elf('.symtab')) - addressof(elf.shdrs)) / sizeof(Elf32_Shdr))
            elf.add_entry(elf('.rel.text'), r, lambda r: r.r_offset)
            text_offset = elf('.text').sh_offset
            if elf[text_offset+i.address+len(push)] == '\xe8': # direct CALL
                elf[text_offset+i.address+len(push)] = '\xe9'
            elif elf[text_offset+i.address+len(push)] == '\xff': # indirect CALL
                elf[text_offset+i.address+len(push)+1] = chr(ord(elf[text_offset+i.address+len(push)+1]) + 0x10)
            else:
                raise Exception('unexpected CALL: %s %s' % (i.mnemonic, i.op_str))
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
    rets = [i.address for i in filter(lambda i: i.bytes == '\xc3', elf.disasm())]
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
        print ('usage: test.py [option+option+..] xxx.o\n'
               '  short_jmp_to_near: rewrite all short JMPs to near JMPs\n'
               '  call_to_jmp: rewrite CALL to PUSH and JMP\n'
               '  protect_switch: add check before jump table indexing\n'
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
