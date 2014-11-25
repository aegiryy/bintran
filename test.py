#!/usr/bin/env python
import sys
import os
import re
from bintran import Elf32

def ret_to_jmp(elf):
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
        print 'usage: test.py [option] xxx.o'
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
