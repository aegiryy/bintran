#!/usr/bin/env python
import sys
from bintran import Elf32, Elf32_Sym
from ctypes import *

def cfi_2(elf):
    '''fill ret_table and modify 0xdeadbeef to actual ret_table'''
    assert elf.ehdr.e_type == 2, 'not an executable?'
    retab = 0
    retabsz = 0
    strtabndx = elf('.symtab').sh_link
    for s in elf('.symtab', Elf32_Sym):
        if elf[elf.shdrs[strtabndx].sh_offset+s.st_name:] == 'ret_table':
            retab = s.st_value
            retabsz = s.st_size
            break
    else:
        assert False, 'ret_table not present?'
    retabndx = 0
    insns = elf.disasm()
    print '  %d CALLs found' % len(filter(lambda i: i.bytes == '\x68\xef\xbe\xad\xde', insns))
    print '  %d RETs found' % len(filter(lambda i: i.bytes == '\xff\x24\x8d\xef\xbe\xad\xde', insns))
    for i in range(len(insns)):
        if insns[i].bytes == '\x68\xef\xbe\xad\xde': # push $0xdeadbeef
            assert retabndx * 4 < retabsz
            elf[elf.addr2off(retab)+retabndx*4:] = string_at(pointer(c_uint(insns[i+1].address+len(insns[i+1]))), 4)
            elf[elf.addr2off(insns[i].address+1):] = string_at(pointer(c_uint(retabndx)), 4)
            retabndx += 1
        elif insns[i].bytes == '\xff\x24\x8d\xef\xbe\xad\xde': # jmp *$0xdeadbeef(,%ecx,4)
            elf[elf.addr2off(insns[i].address+3):] = string_at(pointer(c_uint(retab)), 4)
    return elf

def cfi_1(elf):
    '''rewrite "call addr" to "push index; jmp addr" and
    "ret" to "pop %ecx; check %ecx; jmp *0xdeadbeef(,%ecx,4)"'''
    assert elf.ehdr.e_type == 1, 'not a relocatable?'
    # handle CALLs
    calls = filter(lambda i: i.mnemonic == 'call', elf.disasm())
    print '  %d CALLs found' % len(calls)
    calls.reverse()
    for i in calls:
        push = '\x68\xef\xbe\xad\xde' # "push $0xdeadbeef"
        elf.insert(i.address, push)
        text_offset = elf('.text').sh_offset
        if elf[text_offset+i.address+len(push)] == '\xe8': # direct CALL
            elf[text_offset+i.address+len(push)] = '\xe9'
        elif elf[text_offset+i.address+len(push)] == '\xff': # indirect CALL
            elf[text_offset+i.address+len(push)+1] = chr(ord(elf[text_offset+i.address+len(push)+1]) + 0x10)
        else:
            assert False, 'unexpected CALL? %s %s' % (i.mnemonic, i.op_str)
    # handle RETs (REPZ RETs)
    rets = filter(lambda i: i.bytes == '\xc3' or i.bytes == '\xf3\xc3', elf.disasm())
    print '  %d RETs found' % len(rets)
    rets.reverse()
    # "pop %ecx; and $0x7ff,%ecx; jae $; jmp *0xdeadbeef(,%ecx,4)"
    myret = '\x59\x81\xf9\xff\x07\x00\x00\x0f\x83\xfa\xff\xff\xff\xff\x24\x8d\xef\xbe\xad\xde'
    for r in rets:
        elf.insert(r.address, '\x90' * (len(myret) - len(r))) # need 8 bytes in total
        elf[elf('.text').sh_offset+r.address:] = myret
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
