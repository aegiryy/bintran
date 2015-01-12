Binary Transformer
==================

## What is BT ##
BT is a static binary rewriting engine that can
  * insert new instructions at arbitrary location
  * modify existing instructions
  * create new sections with precise control
  * add entries to existing sections (e.g., `.rel.text`)
  * ...

## Example ##
This example demonstrates how to insert an "nop" instruction
between every two instructions.  
  1. save the following code to **nop.py**
    ```
    import sys
    from bintran import Elf32

    def add_nop(elf):
        iaddrs = [i.address for i in elf.disasm()]
        print '  %d insns found' % len(iaddrs)
        iaddrs.reverse()
        for ia in iaddrs:
            elf.insert(ia, '\x90')
        return elf
    
    if __name__ == '__main__':
        with open(sys.argv[1], 'rb') as obj:
            elf = Elf32(obj.read())
        elf = add_nop(elf)
        with open(sys.argv[1], 'wb') as obj:
            obj.write(str(elf))
    ```
  2. prepare an object file **test.o** (maybe [helloworld]
     (http://en.wikipedia.org/wiki/List_of_Hello_world_program_examples#C)?)
  3. remember the original layout: `objdump -d test.o`
  4. try to insert "nop": `python nop.py test.o`
  5. see the new layout: `objdump -d test.o`
  6. check if such modification breaks the program by linking and running

## What's More ##
`test.py` contains a few other examples such as replacing `CALL` instruction
to semantically same instructions: `PUSH` + `JMP`.  Take a look.
    
