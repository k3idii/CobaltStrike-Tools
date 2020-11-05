import io
import struct
import argparse
from Crypto.Cipher import XOR


class BinStream(io.BytesIO):
  
  def __init__(self, blob):
    self.size = len(blob)
    io.BytesIO.__init__(self, blob)

  def readN(self,n, move=True):
    tmp = self.read(n)
    if len(tmp) < n:
      raise Exception("Not enough data ;/")
    return tmp

  def read_one(self, fmt):
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, self.readN(size))[0]

  def read_2b(self):
    return struct.unpack(">H", self.readN(2) )[0]

  def read_4b(self):
    return struct.unpack(">I", self.readN(4) )[0]

  def available(self):
    return self.size - self.tell()


OPT_TO_ID = dict(
CFG_BeaconType = 1,
CFG_Port = 2,
CFG_SleepTime = 3,
CFG_MaxGetSize = 4,
CFG_Jitter = 5,
CFG_MaxDNS = 6,
CFG_PublicKey = 7,
CFG_C2Server = 8,
CFG_UserAgent = 9,
CFG_HttpPostUri = 10,
CFG_Malleable_C2_Instructions = 11,
CFG_HttpGet_Metadata = 12,
CFG_HttpPost_Metadata = 13,
CFG_SpawnTo = 14,
CFG_PipeName = 15,
CFG_DNS_Idle = 19,
CFG_DNS_Sleep = 20,
CFG_SSH_Host = 21,
CFG_SSH_Port = 22,
CFG_SSH_Username = 23,
CFG_SSH_Password_Plaintext = 24,
CFG_SSH_Password_Pubkey = 25,
CFG_HttpGet_Verb = 26,
CFG_HttpPost_Verb = 27,
CFG_HttpPostChunk = 28,
CFG_Spawnto_x86 = 29,
CFG_Spawnto_x64 = 30,
CFG_CryptoScheme = 31,
CFG_Proxy_Config = 32,
CFG_Proxy_User = 33,
CFG_Proxy_Password = 34,
CFG_Proxy_Behavior = 35,
CFG_Watermark = 37,
CFG_bStageCleanup = 38,
CFG_bCFGCaution = 39,
CFG_KillDate = 40,
CFG_ObfuscateSectionsInfo = 42,
CFG_bProcInject_StartRWX = 43,
CFG_bProcInject_UseRWX = 44,
CFG_bProcInject_MinAllocSize = 45,
CFG_ProcInject_PrependAppend_x86 = 46,
CFG_ProcInject_PrependAppend_x64 = 47,
CFG_ProcInject_Execute = 51,
CFG_ProcInject_AllocationMethod = 52,
CFG_ProcInject_Stub = 53,
CFG_bUsesCookies = 50,
CFG_HostHeader = 54,
)

ID_TO_OPT = {v: k for k, v in OPT_TO_ID.items()}


# first 2 entries in config
CONFIG_PATTERN_1 = b'\x00\x01\x00\x01\x00\x02'
LENGTH_PATTERN_1 = len(CONFIG_PATTERN_1)
CONFIG_PATTERN_2 = b'\x00\x02\x00\x01\x00\x02'
LENGTH_PATTERN_2 = len(CONFIG_PATTERN_2)
MAX_SIZE = 4096
_UNKNOWN = "!UNKNOW!"
def _get_or_unk(a,b):
  return a.get(b, _UNKNOWN)


class CobaltConfigParser(object):
  BEACON_TYPE = {0x0: "HTTP", 0x1: "Hybrid HTTP DNS", 0x2: "SMB", 0x4: "TCP", 0x8: "HTTPS", 0x10: "Bind TCP"}
  ALLOCA_TYPE = {0: "VirtualAllocEx", 1: "NtMapViewOfSection"}
  EXECUTE_TYPE = {0x1: "CreateThread", 0x2: "SetThreadContext", 0x3: "CreateRemoteThread", 0x4: "RtlCreateUserThread", 0x5: "NtQueueApcThread", 0x6: None, 0x7: None, 0x8: "NtQueueApcThread-s"}
    
  def __init__(self, blob):
    self.blob = BinStream(blob)
  


  def parse_stip_null(self, d):
    return d.strip(b'\x00').decode()

  def parse_0x01(self, d):
    return _get_or_unk(self.BEACON_TYPE, d)

  def parse_0x33(self, d):
    data = BinStream(d)
    retval = []
    while data.available()>1:
      v = data.readN(3)
      if v[0] == 0:
        break
      n = self.EXECUTE_TYPE.get(v[0], None)
      if n is None:
        l1 = data.read_4b()
        v1 = self.parse_stip_null(data.readN(l1))
        l2 = data.read_4b()
        v2 = self.parse_stip_null(data.readN(l2))    
        retval.append(f"{v.hex()} {v1}::{v2}")
      else:
        retval.append(f"{v.hex()} {n}")
    return retval

  def parse_0x34(self, d):
    return _get_or_unk(self.ALLOCA_TYPE, d)


  def parse_0x2E(self, d):
    data = BinStream(d)
    size = data.read_4b()
    prep_val = data.readN(size)
    size = data.read_4b()
    appe_val = data.readN(size)
    return dict(prepend = prep_val.hex(), append = appe_val.hex())
 
  parse_0x2F = parse_0x2E

  def parse_0x0C(self, d):
    data = BinStream(d)
    
    ret = [] 
    stack = []

    def _push_value(s,v):
      s.append(v)
      m = f"PUSH: {v}"
      #print(m)
      ret.append(m)
    
    def _commit(s,n,fmt,v):
      m = f'COMMIT {n} : ' + fmt.format(v, ''.join(stack))
      #print(m)
      ret.append(m)
      s.clear()
    
    _read_size_value = lambda: data.readN(data.read_4b())

    while data.available()>4:
      op = data.read_4b()
      if op == 0:
        break
      if op == 10:
        _push_value(stack, _read_size_value().decode() + "\\r\\n" )
      elif op == 7:
        _commit(stack, "headers", "({0}) {1}", data.read_4b() )
      elif op == 8:
        _push_value(stack, '<lower-case-encoded-data>')
      elif op == 2:
        _push_value(stack, _read_size_value().decode() )
      elif op == 1:
        _push_value(stack, _read_size_value().decode() )
      elif op == 6:
        _commit(stack, "header", "{0}:{1}", _read_size_value().decode() )
      elif op == 13:
        _push_value(stack, '<post-payload>' )
      elif op == 5:
        _commit(stack, "body", "{0}={1}", _read_size_value().decode() )
      else:
        print(f"OP {op}")
    #print(ret)
    return ret
  parse_0x0D = parse_0x0C

  def parse_0x28(self, d):
    return "No kill date" if d==0 else d

  parse_0x08 = parse_stip_null  
  parse_0x09 = parse_stip_null
  parse_0x0A = parse_stip_null
  parse_0x1A = parse_stip_null
  parse_0x1B = parse_stip_null
  parse_0x1D = parse_stip_null
  parse_0x1E = parse_stip_null

  def parse_0x0B(self, d):
    data = BinStream(d)
    prog = []
    while data.available()>1:
      op = data.read_4b()
      if not op:
          break
      if op == 1:
          l = data.read_4b()
          prog.append("Remove %d bytes from the end" % l)
      elif op == 2:
          l = data.read_4b()
          prog.append("Remove %d bytes from the beginning" % l)
      elif op == 3:
          prog.append("Base64 decode")
      elif op == 8:
          prog.append("NetBIOS decode 'a'")
      elif op == 11:
          prog.append("NetBIOS decode 'A'")
      elif op == 13:
          prog.append("Base64 URL-safe decode")
      elif op == 15:
          prog.append("XOR mask w/ random key")
    return prog



  def parse_single_record(self):
    idx  = self.blob.read_2b()
    if idx == 0:
      return None
    kind = self.blob.read_2b()
    size = self.blob.read_2b()
    val  = None
    if kind == 1:
      val = self.blob.read_2b()
    elif kind == 2:
      val = self.blob.read_4b()
    elif kind == 3:
      val = self.blob.readN(size)
    else:
      raise Exception("UKNOWN RECORD !")
    
    def _parsed_value(i, d):
      fnc = getattr(self, f"parse_0x{i:02X}", None)
      return None if fnc is None else fnc(d) 

    return dict(
      id = idx,
      hex_id = f"0x{idx:02X}",
      kind = kind,
      size = size,
      name = ID_TO_OPT.get(idx, "UNKNOWN !"),
      raw_value = 'HEX:'+val.hex() if kind==3 else val,
      parsed_value = _parsed_value(idx, val),
    )

  def parse(self):
    records = []
    while self.blob.available() > 6:
      rec = self.parse_single_record()
      if rec is None:
        return records
      #if rec['id'] in [12,13]:
      #  print(rec)
      #  print()
      records.append(rec)

  


def magic_detect_config(raw_data, hint_key = None):

  def _is_this_config(data, offset):
    #offset = 0
    if data[offset : offset+LENGTH_PATTERN_1] != CONFIG_PATTERN_1:
      return False
    #print(f"+{offset} {data[offset:offset+20]} =={LENGTH_PATTERN_1}")
    offset += 2 + LENGTH_PATTERN_1
    #print(f"+{offset} {data[offset:offset+20]} =={LENGTH_PATTERN_2}")
    if data[offset : offset+LENGTH_PATTERN_2] != CONFIG_PATTERN_2:
      return False
    return True

  def _try_to_find_config(data):
    maxi = len(data) - ( LENGTH_PATTERN_1 + LENGTH_PATTERN_2 + 10 )
    i=0
    while i < maxi:
      if _is_this_config(data, i):
        return i
      i += 1
    return None

  keys = range(0xff) if hint_key is None else [hint_key]

  for xor_key in keys:
    #print(f" >> Try key : {xor_key} / 0x{xor_key:02X}")
    alg = XOR.new(bytes([xor_key]))
    xored = alg.decrypt(raw_data)
    pos = _try_to_find_config(xored)
    if pos is not None:
      #print(" ++ FOUND !")
      return xored[pos:pos+MAX_SIZE]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Parses CobaltStrike Beacon config tool")
    parser.add_argument("file_path", help="Path to file (config, dump, pe, etc)")
    parser.add_argument("--key" , help="Hex encoded xor key to use", default=None)
    parser.add_argument("--json", help="json output", action="store_true", default=False)
    parser.add_argument("--yaml", help="yaml output", action="store_true", default=False)
    args = parser.parse_args()
    raw_data = open(args.file_path, "rb").read()
    bin_conf = magic_detect_config(raw_data, None if args.key is None else int(args.key, 16) )
    parser = CobaltConfigParser(bin_conf)
    obj = parser.parse()
    if args.json:
      #print(obj)
      import json
      print(json.dumps(obj))
    elif args.yaml:
      import yaml
      print(yaml.dump(obj))
    else:
      for el in obj:
        print(f"[ ID:{el['id']}/{el['hex_id']} {el['name']} ]")
        pv = el['parsed_value']
        if el['parsed_value'] is not None:
          if type(pv) == list:
            for subel in pv:
              print("  > ",subel)
          else:  
            print("  ", el['parsed_value'])
        else:
          print("  ", el['raw_value'])
        print("")