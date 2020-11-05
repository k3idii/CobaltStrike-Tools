import pefile
import sys
import struct
import Crypto.Cipher.XOR as XOR

if len(sys.argv) != 2:
  raise Exception('Usae: code.py [path_to_pe_file]')
FILENAME = sys.argv[1]
OUTFILE  = f'{FILENAME}_fix.bin'
binary_data = open(FILENAME, 'rb').read()


def _unpack_ex(fmt, data=None, read_cb=None, into=None):
  if data is None and read_cb is None:
    raise Exception("DATA or readCB !")
  if data is None:
    size = struct.calcsize(fmt)
    data = read_cb(size)
  res  = struct.unpack(fmt, data)
  if into is None:
    if len(res) == 1:
      return res[0]
    else:
      return res
  else:
    return dict(zip(info,res))



class BinStream(object):
  def __init__(self, d):
    self.data = bytearray(d)
    self.ptr = 0

  def read_n(self,n, move=True):
    tmp = self.data[self.ptr : self.ptr+n]
    if move:
      self.ptr += n
    return tmp

  def read_fmt(self, fmt, into=None):
    size = struct.calcsize(fmt)
    data = self.read_n(size)
    return _unpack_ex(fmt, data, into)


  def available(self):
    return len(self.data) - self.ptr

  def at_patch(self, where, what):
    i = 0
    #print(what)
    #print(self.data[where:where+20])
    for b in what:
      self.data[where + i] = b
      i+=1
    #print(self.data[where:where+20])

  def at_read_n(self, at, n):
    return bytes(self.data[at:at+n])
  
  def at_read_fmt(self, fmt, into=None):
    return _unpack_ex(fmt, read_cb=self.at_read_n, into=into)

  def save(self, fn):
    open(fn,'wb').write(self.data)


def byte_till(bts, stop, include_stop=False):
  i=0
  while bts[i] != stop:
    i+=1
  if include_stop:
    return bts[:i+1]
  else: 
    return bts[:i]


pe = pefile.PE(FILENAME)
stream = BinStream(binary_data)

key = 0x00FF & pe.FILE_HEADER.NumberOfSymbols
print(f"Xor key : {key} / 0x{key:04X}")

algo = XOR.new(key=bytes([key]))

print("## ## FIXING SECTION NAMES ## ##")
for section in pe.sections:
    print(f' SECTION : {section.Name} @ {section.get_file_offset()}')
    data_ptr = section.get_file_offset()
    enc_name = stream.at_read_n(data_ptr, 8)
    dec_name = algo.decrypt(enc_name)
    print(f'   -  > Decrypted name : {dec_name}')
    stream.at_patch(data_ptr, dec_name)
    stream.save(OUTFILE)
print()

print("## ## FIXING IMPORTS ## ##")

rva_of_import_table = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress

offset = rva_of_import_table
print(f' >> Import Table start @ {offset:08X} .. ')

while True:
  if pe.get_data(offset, 2)[0]== 0:
    break
  rva_of_dllname = pe.get_dword_at_rva(offset + 12)
  off_of_dllname = pe.get_offset_from_rva(rva_of_dllname) 
  print(f" + DLL NAME  @ 0x{rva_of_dllname:08X} ~~> {off_of_dllname:08X}")

  enc_dll_name = stream.at_read_n(off_of_dllname, 30)
  dec_dll_name = byte_till(algo.decrypt(enc_dll_name), 0, include_stop=True)
  stream.at_patch(off_of_dllname, dec_dll_name)
  print(f"  DLL NAME: {dec_dll_name} ")

  rva_of_names   = pe.get_dword_at_rva(offset + 0)
  #off_of_name    = pe.get_offset_from_rva(rva_of_names) 
  print(f" + NAMES @ 0x{rva_of_names:08X} ") #~~> {off_of_name:08X}")
  for entry in pe.get_import_table(rva_of_names):
    hx = hex(entry.AddressOfData)[:4]
    if  hx[:4] == "0x80":
      print(f"  >> SKIP ! {hex(entry.AddressOfData)}")
      #print(entry)
      continue
    off = pe.get_offset_from_rva(entry.AddressOfData)
    enc = stream.at_read_n(off, 100)
    dec = algo.decrypt(enc)
    name = byte_till(dec[2:], 0, include_stop=1)
    entry_len = 2 + len(name)
    stream.at_patch(off, dec[:entry_len])
    print(f"   FIXED: {name}")
  offset += 0x14
stream.save(OUTFILE)
  