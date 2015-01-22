#!/usr/bin/env python
import sys
from bintran import Elf32, Elf32_Sym, assemble
from ctypes import *

def cfi_2(elf):
    '''fill ret_table and modify 0xdeadbeef to actual ret_table'''
    assert elf.ehdr.e_type == 2, 'not an executable?'
    strtabndx = elf('.symtab').sh_link
    rtsym = next((s for s in elf('.symtab', Elf32_Sym)\
            if elf[elf.shdrs[strtabndx].sh_offset+s.st_name:] == 'ret_table'), None)
    assert rtsym, 'ret_table is not found'
    rtndx = 0
    insns = elf.disasm()
    pcode = assemble('push 0xdeadbeef')
    jcode = assemble('jmp dword [0xdeadbeef+ecx*4]')
    print '  %d CALLs found' % len(filter(lambda i: i.bytes == pcode, insns))
    print '  %d RETs found' % len(filter(lambda i: i.bytes == jcode, insns))
    for i in range(len(insns)):
        if insns[i].bytes == pcode:
            assert rtndx * 4 < rtsym.st_size
            raddr = insns[i+1].address + len(insns[i+1])
            elf[elf.addr2off(rtsym.st_value)+rtndx*4:] = string_at(pointer(c_uint(raddr)), 4)
            elf[elf.addr2off(insns[i].address+1):] = string_at(pointer(c_uint(rtndx)), 4)
            rtndx += 1
        elif insns[i].bytes == jcode:
            elf[elf.addr2off(insns[i].address+3):] = string_at(pointer(c_uint(rtsym.st_value)), 4)
    return elf

def cfi_1(elf):
    '''rewrite "call addr" to "push index; jmp addr" and
    "ret" to "pop %ecx; check %ecx; jmp *0xdeadbeef(,%ecx,4)"'''
    assert elf.ehdr.e_type == 1, 'not a relocatable?'
    elf.flatten()
    # rewrite "calls"
    calls = filter(lambda i: i.mnemonic == 'call', elf.disasm())
    print '  %d CALLs found' % len(calls)
    calls.reverse()
    code = assemble('push 0xdeadbeef')
    for i in calls:
        # insert "push 0xdeadbeef"
        elf.insert(i.address, code)
        # rewrite "call dest" to "jmp dest"
        call_offset = elf('.text').sh_offset + i.address + 5
        if elf[call_offset] == '\xe8': # direct "call"
            elf[call_offset] = '\xe9'
        elif elf[call_offset] == '\xff': # indirect "call"
            elf[call_offset+1] = chr(ord(elf[call_offset+1]) + 0x10)
        else:
            assert False, 'unexpected CALL? %s' % str(i)
    # rewrite "rets" and "repz rets"
    rets = filter(lambda i: i.mnemonic == 'ret' or
            i.mnemonic == 'repz ret', elf.disasm())
    print '  %d RETs found' % len(rets)
    rets.reverse()
    code = assemble(('pop ecx\n'
                     'cmp ecx, 0x800\n'
                     'jae near $\n'
                     'jmp dword [0xdeadbeef+ecx*4]\n'))
    for r in rets:
        elf.insert(r.address, '\x90'*(len(code)-len(r)))
        elf[elf('.text').sh_offset+r.address:] = code
    return elf

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'cfi.py [phase] [binary_path]'
        sys.exit(0)
    for objfile in sys.argv[2:]:
        print '%s' % objfile
        with open(objfile, 'rb') as f:
            elf = Elf32(f.read())
        elf = cfi_1(elf) if sys.argv[1] == '1' else cfi_2(elf)
        with open(objfile, 'wb') as f:
            f.write(str(elf))
