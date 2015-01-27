#!/usr/bin/env python
import sys
import os
import re
from bintran import Insn, Elf32, Elf32_Sym, assemble
from ctypes import *

def is_ret(insns, i):
    return insns[i].bytes == '\xff\x24\x8d\xef\xbe\xad\xde'

def is_call(insns, i):
    return insns[i-1].bytes == '\x68\xef\xbe\xad\xde'

def disasm(exe):
    '''almost a clone of Elf32.disasm except adding label info'''
    current = ''
    insns = []
    for l in os.popen('objdump -j .text -d %s' % exe):
        r = re.search(r'[0-9a-f]{8} <(.*)>:', l)
        if r:
            current = r.group(1)
            continue
        r = re.search(r'([0-9a-f]+):\s*(([0-9a-f]{2} )+)\s*([a-z]*)\s*(.*)', l)
        if not r:
            continue
        ad, bs = int(r.group(1), 16), r.group(2).replace(' ', '').decode('hex')
        mn, op = r.group(4), r.group(5)
        if not mn:
            insns[-1].bytes += bs
        else:
            insns.append(Insn(ad, bs, mn, op))
            insns[-1].label = current
    return insns

def find_rets(insns, label):
    '''find the return instructions corresponding to "call label"'''
    # a "function" transfers control to another function without using "call"
    FALLTHROUGH = {
            'phys_copy': ('phys_copy_fault', 'phys_copy_fault_in_kernel'),
            'copy_msg_from_user': ('__copy_msg_from_user_end',),
            'copy_msg_to_user': ('__copy_msg_to_user_end',),
            'fxrstor': ('__fxrstor_end',),
            'frstor': ('__frstor_end', '__frstor_failure'),
            'phys_memset': ('memset_fault', 'memset_fault_in_kernel'),
            'x86_load_kerncs': ('newcs',),
    }
    # "ret" within the function
    linsns = filter(lambda i: insns[i].label == label, range(len(insns)))
    rets = filter(lambda i: is_ret(insns, i), linsns)
    # follow tail calls
    for i in filter(lambda i: not is_call(insns, i) and insns[i].mnemonic == 'jmp', linsns):
        r = re.search(r'<([^+]*)>', insns[i].op_str)
        if not r:
            continue
        rets += find_rets(insns, r.group(1)) if r.group(1) != label else []
    # follow fall-through functions
    if label in FALLTHROUGH:
        rets = sum([find_rets(insns, l) for l in FALLTHROUGH[label]], rets)
    return rets

def verify_policy(ret_and_calls):
    calls = set(sum(ret_and_calls.values(), []))
    for c in calls:
        call_sets = filter(lambda cs: c in cs, ret_and_calls.values())
        assert len(set([cs.index(c) for cs in call_sets])) == 1,\
                'a target must have the same index in all lists'

def minix_policy(insns):
    '''this function is specific to a modified MINIX 3.2.1'''
    # handle system calls (i.e., do_*) first
    do_rets = filter(lambda i: is_ret(insns, i) and insns[i].label.startswith('do_'), range(len(insns)))
    # find the only indirect call remained in the program
    the_indirect_call = filter(lambda i: is_call(insns, i) and insns[i].op_str.startswith('*'), range(len(insns)))
    assert len(the_indirect_call) == 1
    the_indirect_call = the_indirect_call[0]
    ret_and_calls = {}
    for i in do_rets:
        ret_and_calls[i] = [the_indirect_call]
    # handle other calls
    calls = filter(lambda i: is_call(insns, i), range(len(insns)))
    rets = filter(lambda i: is_ret(insns, i), range(len(insns)))
    assert calls and rets
    for c in calls:
        r = re.search(r'<(.*)>', insns[c].op_str)
        if not r:
            continue
        assert '+' not in r.group(1)
        for r in find_rets(insns, r.group(1)):
            ret_and_calls[r] = ret_and_calls.get(r, []) + [c]
    # adjust the index of a target if it differs in multiple lists
    for c in calls:
        call_sets = filter(lambda cs: c in cs, ret_and_calls.values())
        if len(set([cs.index(c) for cs in call_sets])) > 1:
            for i in range(len(call_sets[1]), len(call_sets[0])):
                call_sets[1].insert(0, 0)
    verify_policy(ret_and_calls)
    return ret_and_calls

def cfi_minix(elf):
    assert elf.ehdr.e_type == 2, 'not an executable?'
    strtabndx = elf('.symtab').sh_link
    rtsym = next((s for s in elf('.symtab', Elf32_Sym)\
            if elf[elf.shdrs[strtabndx].sh_offset+s.st_name:] == 'ret_table'), None)
    assert rtsym, 'ret_table is not found'
    rtndx = 0
    insns = disasm(sys.argv[2])
    ret_and_calls = minix_policy(insns)
    for r, cs in ret_and_calls.items():
        for i in range(len(cs)):
            if not cs[i]:
                continue # skip padding calls
            raddr = insns[cs[i]].address + len(insns[cs[i]])
            # fill table
            elf[elf.addr2off(rtsym.st_value)+(rtndx+i)*4:] = string_at(pointer(c_uint(raddr)), 4)
            # modify push index
            push_offset = elf.addr2off(insns[cs[i]-1].address)
            assert elf[push_offset+1:push_offset+5] == '\xef\xbe\xad\xde' or\
                    elf[push_offset+1:push_offset+5] == string_at(pointer(c_uint(i)), 4), str(insns[cs[i]])
            elf[elf.addr2off(insns[cs[i]-1].address)+1:] = string_at(pointer(c_uint(i)), 4)
        # update cmp operand to the number of sub-table entries
        assert elf[elf.addr2off(insns[r-2].address)+2:].startswith('\xef\xbe\xad\xde')
        elf[elf.addr2off(insns[r-2].address)+2:] = string_at(pointer(c_uint(len(cs))), 4)
        # update ret table to the sub-table
        assert elf[elf.addr2off(insns[r].address)+3:].startswith('\xef\xbe\xad\xde')
        elf[elf.addr2off(insns[r].address)+3:] = string_at(pointer(c_uint(rtsym.st_value+rtndx*4)), 4)
        rtndx += len(cs)
        assert rtndx * 4 < rtsym.st_size
    # differentiate all unmatched calls for debugging when they are accidentally used
    count = 0
    pushes = filter(lambda i: i.bytes == '\x68\xef\xbe\xad\xde', insns)
    for i in range(len(pushes)):
        push_offset = elf.addr2off(pushes[i].address)
        if elf[push_offset+1:push_offset+5] == '\xef\xbe\xad\xde':
            elf[push_offset+1:] = string_at(pointer(c_uint(0xdeadbeef+i)), 4)
            count += 1
    print '  %d unmatched CALLs' % count
    return elf

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
    ccode = assemble('cmp ecx, 0xdeadbeef')
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
        elif insns[i].bytes == ccode:
            elf[elf.addr2off(insns[i].address+2):] = string_at(pointer(c_uint(rtsym.st_size/4)), 4)
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
    # rewrite "ret" and "repz ret"
    rets = filter(lambda i: i.mnemonic == 'ret' or i.op_str == 'ret', elf.disasm())
    print '  %d RETs found' % len(rets)
    rets.reverse()
    code = assemble(('pop ecx\n'
                     'cmp ecx, 0xdeadbeef\n'
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
        elf = globals()['cfi_%s' % sys.argv[1]](elf)
        with open(objfile, 'wb') as f:
            f.write(str(elf))
