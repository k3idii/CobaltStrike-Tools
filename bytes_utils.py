"""
  ByteArray tools
"""
import io
import struct
import re

SIZE_DWORD = 4
SIZE_WORD  = 2

def netbios_encode(bin_string, from_char=b'a'):
  """nibble-encoder"""
  from_char = from_char[0]
  return b''.join([bytes([(c>>4)+from_char,(c&0xF)+from_char]) for c in bin_string])

def netbios_decode(bin_string, from_char=b'a'):
  """nibble-decoder"""
  retval = []
  from_char = from_char[0]
  for i in range(0,len(bin_string),2):
    a,b = bin_string[i:i+2]
    retval.append( (a-from_char)*0x10 + (b-from_char) )
  return bytes(retval)


class BinStream(io.BytesIO):
  """ Extended version of BytesIO """

  def __init__(self, blob):
    self.size = len(blob)
    io.BytesIO.__init__(self, blob)

  def read_n(self, how_many):
    """ Read exacly N bytes, raise exception otherwise"""
    tmp = self.read(how_many)
    if len(tmp) < how_many:
      raise Exception("Not enough data ;/")
    return tmp

  def read_one(self, fmt):
    """ Read exacly ONE format data """
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, self.read_n(size))[0]

  def read_byte(self):
    """ read one byte """
    return struct.unpack("B", self.read_n(1))[0]

  def read_n_word(self):
    """ read net-order WORD """
    return struct.unpack(">H", self.read_n(SIZE_WORD))[0]

  def read_n_dword(self):
    """ read net-worder DWORD """
    return struct.unpack(">I", self.read_n(SIZE_DWORD))[0]

  def read_h_word(self):
    """ read host-order WORD """
    return struct.unpack("<H", self.read_n(SIZE_WORD))[0]

  def read_h_dword(self):
    """ read host-worder DWORD """
    return struct.unpack("<I", self.read_n(SIZE_DWORD))[0]

  def available(self):
    """ return how much data left in buffer """
    return self.size - self.tell()


def chunks_generator(l, n):
  n = max(1, n)
  return (l[i:i+n] for i in range(0, len(l), n))


def bytes_find_generator(data, pattern):
  pos = 0
  while True:
    tmp = data.find(pattern, pos)
    if tmp == -1:
      break
    yield tmp
    pos = tmp+1



class SinglePattern:
  def __init__(self, start, pattern, encoder=None):
    self.start = start
    self.pattern = pattern
    if encoder is not None:
      #print("ENCODER => ", end='')
      self.pattern = encoder(pattern)
    self.size = len(pattern)
    self.end = self.start + self.size
    #print(self)
   
  def test(self, data, base=0):
    #print("TEST : ", list(chunks_generator(data[base+self.start:][:40].hex(), 8) ) )
    #print("MATCH: ", list(chunks_generator(self.pattern.hex()    , 8) ) )
    #print(self)
    #print(data[base + self.start : base + self.end ], self.pattern)
    return data[base + self.start : base + self.end ] == self.pattern

  def __str__(self):
    return f"{self.start}...{self.end} == {self.pattern}"

NOT_FOUND = -1

class AlmostLikeYara:
  patterns = None
  total_size = 0

  def __init__(self, pattern, encoder=None):
    chunk = ''
    offset = 0
    self.patterns = list()
    for element in re.split('[^0-9A-Fa-f?]+',pattern):
      if element != '??':
        chunk += element
        continue
      # it is "??"
      offset += 1
      if chunk == '': # buffer is empty ..
        continue
      obj = SinglePattern(offset -1 , bytes.fromhex(chunk), encoder)
      self.patterns.append(obj)
      offset += obj.size
      chunk = ''
    self.total_size = offset

  def test_data(self, data, offset=0):
    match_cnt = 0
    for element in self.patterns:
      if element.test(data, offset):
        match_cnt +=1
      else:
        return False
    return True

  def find_in_data(self, data):
    max_size = len(data) - self.total_size
    if max_size < 1:
      return NOT_FOUND
    cursor = 0
    while cursor < max_size:
      success = self.test_data(data, cursor)
      if success:
        return cursor
      cursor += 1
    return NOT_FOUND

  def smart_find_callback(self, data, candidate_generator):
    first = self.patterns[0]
    #print(first, len(data))
    for candidate in candidate_generator(first.pattern):
      #print("Candidate:", candidate)
      result = self.test_data(data, candidate)
      if result:
        return candidate
    return NOT_FOUND

  def smart_search(self, data):
    
    def _gen(pattern):
      for offset in bytes_find_generator(data, pattern):
        yield offset

    return self.smart_find_callback(data, _gen)

