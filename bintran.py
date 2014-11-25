#!/usr/bin/env python
import os
import sys
import re
from uuid import uuid4
from ctypes import *

GCCPREFIX = os.environ.get('GCCPREFIX', '')

class Elf32_Ehdr(Structure):
    _fields_ = [
            ('e_ident', c_char * 16),
            ('e_type', c_ushort),
            ('e_machine', c_ushort),
            ('e_version', c_uint),
            ('e_entry', c_uint),
            ('e_phoff', c_uint),
            ('e_shoff', c_uint),
            ('e_flags', c_uint),
            ('e_ehsize', c_ushort),
            ('e_phentsize', c_ushort),
            ('e_phnum', c_ushort),
            ('e_shentsize', c_ushort),
            ('e_shnum', c_ushort),
            ('e_shstrndx', c_ushort)]

class Elf32_Shdr(Structure):
    _fields_ = [
            ('sh_name', c_uint),
            ('sh_type', c_uint),
            ('sh_flags', c_uint),
            ('sh_addr', c_uint),
            ('sh_offset', c_uint),
            ('sh_size', c_uint),
            ('sh_link', c_uint),
            ('sh_info', c_uint),
            ('sh_addralign', c_uint),
            ('sh_entsize', c_uint)]

class Elf32_Sym(Structure):
    _fields_ = [
            ('st_name', c_uint),
            ('st_value', c_uint),
            ('st_size', c_uint),
            ('st_info', c_uint8),
            ('st_other', c_uint8),
            ('st_shndx', c_ushort)]

class Elf32_Rel(Structure):
    _fields_ = [
            ('r_offset', c_uint),
            ('r_info', c_uint)]

class Elf32(object):
    def __init__(self, binary):
        self.binary = bytearray(binary)
        self.ehdr = Elf32_Ehdr.from_buffer(self.binary)
        self.shdrs = (self.ehdr.e_shnum * Elf32_Shdr).from_buffer(self.binary, self.ehdr.e_shoff)

    def __str__(self):
        return str(self.binary)

    def __len__(self):
        return len(self.binary)

    def __setitem__(self, q, value):
        offset, ctype = q if type(q) is tuple else (q, c_char)
        ctype.from_buffer(self.binary, offset).value = value

    def __getitem__(self, q):
        offset, ctype = q if type(q) is tuple else (q, c_char)
        return ctype.from_buffer(self.binary, offset).value

    def __getslice__(self, offset, end):
        assert 0 <= offset < len(self) and offset < end
        length = -1 if end == sys.maxint else min(end-offset, len(self)-offset)
        return string_at(c_char_p(str(self.binary[offset:])), length)

    def __setslice__(self, offset, end, value):
        assert 0 <= offset < len(self) and offset < end
        end = min(end, len(self), offset+len(value))
        self.binary[offset:end] = value[:end-offset]

    def __call__(self, name, ctype=None):
        '''return section header or section if its type is specified'''
        for sh in self.shdrs:
            if self[self.shdrs[self.ehdr.e_shstrndx].sh_offset+sh.sh_name:] != name:
                continue
            if ctype is None:
                return sh
            return (sh.sh_size/sizeof(ctype) * ctype).from_buffer(self.binary, sh.sh_offset)
        return None if ctype is None else []

    def disasm(self):
        tmpfile = '.%s.o' % uuid4()
        with open(tmpfile, 'wb') as f:
            f.write(str(self))
        insns = os.popen('%sobjdump -d %s' % (GCCPREFIX, tmpfile)).readlines()
        os.unlink(tmpfile)
        return insns

    def insert(self, off_in_text, payload=''):
        '''insert a sequence of instructions at off_in_text'''
        assert self.ehdr.e_type == 1, 'not an object file?'
        _text = self('.text')
        assert _text, 'no .text section?'
        assert addressof(_text) == addressof(self.shdrs[1]), '.text index is not 1?'
        syms = self('.symtab', Elf32_Sym)
        # update .text section
        updts = {}
        for l in self.disasm():
            r = re.search(r'(?<=<)[^>]*', l)
            if not r: # a possible direct CALL/JMP
                continue
            r = re.search(r'([0-9a-f]+):\s*(([0-9a-f]{2} )+)', l)
            if not r: # skip function start like <foo>:
                continue
            cia, insn = int(r.group(1), 16), r.group(2).replace(' ', '').decode('hex')
            opnd_size = 1 if len(insn) == 2 else 4
            opnd_text_off = cia + len(insn) - opnd_size
            for r in self('.rel.text', Elf32_Rel):
                if opnd_text_off == r.r_offset: # skip relocation entries
                    break
            else: # a real direct CALL/JMP
                ctype = {1: c_int8, 4: c_int}[opnd_size]
                tgt = cia + len(insn) + self[_text.sh_offset+opnd_text_off, ctype]
                new_tgt = tgt + (len(payload) if tgt >= off_in_text else 0)
                new_cia = cia + (len(payload) if cia >= off_in_text else 0)
                new_off = new_tgt - new_cia - len(insn)
                assert -(1 << (opnd_size * 8 - 1)) <= new_off < 1 << (opnd_size * 8 - 1),\
                        'operand at 0x%x may overflow' % cia
                updts[_text.sh_offset+opnd_text_off, ctype] = new_off
        for k, v in updts.items(): # update CALL/JMP operands if reach here
            self[k] = v
        # update relocation entries
        for sh in self.shdrs:
            if sh.sh_type != 9: # SHT_REL
                continue
            rels = (sh.sh_size/sizeof(Elf32_Rel) * Elf32_Rel).from_buffer(self.binary, sh.sh_offset)
            for r in rels:
                s = syms[r.r_info>>8]
                if r.r_info & 0xff == 1 and s.st_info & 0xf == 3 and s.st_shndx == 1: # R_386_32 and .text
                    addend = self[self.shdrs[sh.sh_info].sh_offset+r.r_offset, c_uint]
                    if addend >= off_in_text:
                        self[self.shdrs[sh.sh_info].sh_offset+r.r_offset, c_uint] = addend + len(payload)
                if sh.sh_info == 1: # update offsets of relocation entries in .text section
                    if r.r_offset >= off_in_text:
                        r.r_offset += len(payload)
        # update symbols of .text section
        for s in syms:
            if s.st_shndx != 1: # [1] .text
                continue
            if s.st_value > off_in_text:
                s.st_value += len(payload)
            elif s.st_value <= off_in_text < s.st_value + s.st_size:
                s.st_size += len(payload)
        # update section header table offset
        self.ehdr.e_shoff += len(payload)
        # update text section header
        _text.sh_size += len(payload)
        # update later sections
        for sh in self.shdrs:
            if sh.sh_offset <= _text.sh_offset:
                continue
            sh.sh_offset += len(payload)
        # update binary
        binary = str(self)
        self.binary = bytearray(''.join((binary[:_text.sh_offset+off_in_text],
                                         payload,
                                         binary[_text.sh_offset+off_in_text:])))
