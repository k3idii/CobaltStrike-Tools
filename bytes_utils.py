"""
  ByteArray tools
"""
import io
import struct
import re

try:
  from minidump.minidumpfile import MinidumpFile
except ImportError:
  MinidumpFile = None


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
    byte1, byte2 = bin_string[i:i+2]
    retval.append( (byte1-from_char)*0x10 + (byte2-from_char) )
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


def _chunks_generator(l, n):
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
  """ Single memory pattern. Can be used to test memory chunk if matches """
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
  """ super simple binary pattern matching engine """
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


class AbstractDataProvider:
  config_at = NOT_FOUND
  data_encoder = None
  source = None

  def __init__(self, source, *a, **kw):
    self.source = source
    self.setup(*a, **kw)
  
  def setup(self):
    pass

  def config_found(self, addr):
    self.config_at = addr
  
  def set_encoder(self, enc):
    self.data_encoder = enc

  def read(self, addr, size):
    chunk = self._raw_read(addr, size)
    if self.data_encoder:
      return self.data_encoder(chunk)
    return chunk

  def find_using_func(self, func):
    return NOT_FOUND


class BinaryData(AbstractDataProvider):
  """ Interface to flat binary file """
    ## TODO: implement buffered reader/mapFile for large flat files ?

  data = b''
  def setup(self):
    self.data = open(self.source,'rb').read()

  def replace_data(self, data):
    self.data = data

  def find_using_func(self, func):
    """ find using callback, feed w/ data """
    result = func(self.data)
    self.found_at = result
    return result

  def _raw_read(self, addr, size):
    """ read ( address, size ) """
    return self.data[addr:addr+size]



class MinidumpData(AbstractDataProvider):
  """ interface for minidump file format """

  def setup(self):
    if MinidumpFile is None:
      raise Exception("Need to have working minidump module !")
    self.obj = MinidumpFile.parse(self.source)
    self._reader = self.obj.get_reader()


  def find_using_func(self, func):
    """ find using callback, feed w/ data """
    for seg in self._reader.memory_segments:
      blob = seg.read(seg.start_virtual_address, seg.size, self._reader.file_handle)
      result = func(blob)
      if result != NOT_FOUND:
        self.found_at = result + seg.start_virtual_address
        return result
    return NOT_FOUND

  def _raw_read(self, addr, size):
    """ read ( address, size ) """
    return self._reader.read(addr, size)
