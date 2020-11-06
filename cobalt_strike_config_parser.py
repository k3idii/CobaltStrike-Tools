import io
import struct
import argparse
import pprint
from Crypto.Cipher import XOR


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

  def read_2b(self):
    """ read net-order WORD """
    return struct.unpack(">H", self.read_n(2) )[0]

  def read_4b(self):
    """ read net-worder DWORD """
    return struct.unpack(">I", self.read_n(4) )[0]

  def available(self):
    """ return how much data left in buffer """
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

ID_TO_OPT = {value: k for k, value in OPT_TO_ID.items()}

BEACON_TYPE = {0x0: "HTTP", 0x1: "Hybrid HTTP DNS",
              0x2: "SMB", 0x4: "TCP", 0x8: "HTTPS", 0x10: "Bind TCP"}
ALLOCA_TYPE = {0: "VirtualAllocEx", 1: "NtMapViewOfSection"}
EXECUTE_TYPE = {0x1: "CreateThread", 0x2: "SetThreadContext",
                0x3: "CreateRemoteThread", 0x4: "RtlCreateUserThread",
                0x5: "NtQueueApcThread", 0x6: None, 0x7: None, 0x8: "NtQueueApcThread-s"}

HTTP_NEWLINE = "\r\n"

# first 2 entries in config
CONFIG_PATTERN_1 = b'\x00\x01\x00\x01\x00\x02'
LENGTH_PATTERN_1 = len(CONFIG_PATTERN_1)
CONFIG_PATTERN_2 = b'\x00\x02\x00\x01\x00\x02'
LENGTH_PATTERN_2 = len(CONFIG_PATTERN_2)
MAX_SIZE = 4096
_UNKNOWN = "!UNKNOW!"
def _get_or_unk(a,b):
  return a.get(b, _UNKNOWN)

def _bytes_strip(d):
  return d.strip(b'\x00').decode()


class ConfigEntry(object):
  """
    Store single config entry
  """
  def __init__(self, idx, kind, size, data):
    self.id = idx
    self.hex_id = f"0x{idx:02X}"
    self.name = ID_TO_OPT.get(idx, _UNKNOWN)
    self.kind = kind
    self.size = size
    self.data = data
    self.parsed = None

  def _to_json(self):
    return self.__dict__

  def short_str(self):
    return f"[ ID:{self.id}/{self.hex_id} type:{self.kind} size:{self.size:<4} name:{self.name} ]"

  def __str__(self):
    def _try_to_str(d):
      try:
        return _bytes_strip(d)
      except:
        return str(d)
    retval = [ self.short_str() ]
    if self.parsed is not None:
      retval.append("  " + pprint.pformat(self.parsed, indent=2))
    else:
      if self.kind == 3:
        retval.append("  " + _try_to_str(self.data))
      else:
        retval.append("  " + str(self.data))
    retval.append('')
    return '\n'.join(retval)


class CobaltConfigParser(object):
  """
    Parse & store config
  """

  def __init__(self, blob):
    self.blob = BinStream(blob)
    self.records = []
    self.records_by_id = dict()

  def safe_get_opt(self, idx=None, opt=None):
    if idx is None:
      idx = OPT_TO_ID[opt]
    return self.records_by_id.get(idx, None)

  def parse_0x01(self, d):
    return BEACON_TYPE.get(d.data, _UNKNOWN)

  def parse_0x0B(self, d):
    s = BinStream(d.data)
    retval = []
    while s.available()>1:
      op = s.read_4b()
      if not op:
        break
      if op == 1:
        retval.append("Remove {0} bytes from the end".format(s.read_4b()))
      elif op == 2:
        retval.append("Remove {0} bytes from the beginning".format(s.read_4b()))
      elif op == 3:
        retval.append("Base64 decode")
      elif op == 8:
        retval.append("decode nibbles 'a'")
      elif op == 11:
        retval.append("decode nibbles 'A'")
      elif op == 13:
        retval.append("Base64 URL-safe decode")
      elif op == 15:
        retval.append("XOR mask w/ random key")
    return retval

  def parse_0x2E(self, d):
    #print(d.data)
    data = BinStream(d.data)
    size = data.read_4b()
    prep_val = data.read_n(size)
    size = data.read_4b()
    appe_val = data.read_n(size)
    return dict(prepend = prep_val.hex(), append = appe_val.hex())

  parse_0x2F = parse_0x2E

  def parse_0x0C(self, d):
    s = BinStream(d.data)
    opts = dict(
      headers = '',
      path = '',
      body = '',
    )
    code = []
    tmp_buf = ""

    _path_not_empty = lambda : len(opts['path'])>1
    _read_len_value = lambda x: x.read_n(x.read_4b()).decode()

    while s.available()>4:
      #print("   BUFFERS ", tmp1,"   #  ",tmp_buf)
      op = s.read_4b()
      op_str = f"[{op:02X}] "
      #print(" OP:",op, d.data[s.tell():][:20] )
      if op == 0:
        host_entry = self.safe_get_opt(opt='CFG_HostHeader')
        host_str = _bytes_strip(host_entry.data)
        if len(host_str)>1:
          opts['headers'] += host_str + HTTP_NEWLINE
        break
      elif op == 1:
        value = _read_len_value(s)
        tmp_buf = tmp_buf + value
        op_str += f"append {value} to tmp_buf"
      elif op == 2:
        value = _read_len_value(s)
        tmp_buf = value + tmp_buf
        op_str += f"prepend {value} to tmp_buf"
      elif op == 4:
        opts['body'] = tmp_buf
        op_str += f"set BODY to tmp_buf: {tmp_buf}"
      elif op == 5:
        value = _read_len_value(s)
        if _path_not_empty():
          opts['path'] = f"{opts['path']}&{value}={tmp_buf}"
        else:
          opts['path'] = f"?{value}={tmp_buf}"
        op_str += f"add GET PARAM from tmp_buf : {value}={tmp_buf}"
      elif op == 6:
        value = _read_len_value(s)
        hdr = f"{value}: {tmp_buf}"
        opts['headers'] = opts['headers'] + hdr + HTTP_NEWLINE
        op_str += f"add header from TMPtmp_buf2 => {value} : {tmp_buf}"
      elif op == 7:
        value = s.read_4b()
        tmp_buf = f"<DATA:{value}>"
        op_str += f"load {tmp_buf} to tmp_buf"
      elif op == 8:
        tmp_buf = f"<LOCASE_ENCODE({tmp_buf})>"
        op_str += "lower-case encode tmp_buf"
      elif op == 9:
        value = _read_len_value(s)
        if _path_not_empty():
          opts['path']= f"{opts['path']}&{value}"
        else:
          opts['path'] = f"?{value}"
        op_str += f"add GET PARAM: {value}"
      elif op == 10:
        value = _read_len_value(s)
        opts['headers'] = opts['headers'] + value + HTTP_NEWLINE
        op_str += f"ADD HEADER: {value}"
      elif op == 13:
        tmp_buf = f"<BASE64_URL({tmp_buf})>"
        op_str += " BASE64_URLSAFE(tmp_buf)"
      else:
        op_str += " <-- implement me"
      #print(" COMMAND : ",op_str)
      code.append(op_str)
    #import yaml
    #print(yaml.dump(opts))
    #print(yaml.dump(code))
    opts['_code'] = code
    return opts



  parse_0x0D = parse_0x0C

  def parse_0x28(self, d):
    return "No kill date set!" if d.data==0 else d.data

  parse_to_str = lambda a,b: _bytes_strip(b.data)
  parse_0x08 = parse_to_str
  parse_0x09 = parse_to_str
  parse_0x0A = parse_to_str
  parse_0x0F = parse_to_str
  parse_0x1A = parse_to_str
  parse_0x1B = parse_to_str
  parse_0x1D = parse_to_str
  parse_0x1E = parse_to_str

  def parse_0x33(self, d):
    data = BinStream(d.data)
    retval = []
    while data.available()>1:
      value = data.read_n(3)
      if value[0] == 0:
        break
      name = EXECUTE_TYPE.get(value[0], None)
      if name is None:
        len1 = data.read_4b()
        val1 = _bytes_strip(data.read_n(len1))
        len2 = data.read_4b()
        val2 = _bytes_strip(data.read_n(len2))
        retval.append(f"{value.hex()} {val1}::{val2}")
      else:
        retval.append(f"{value.hex()} {name}")
    return retval

  def parse_0x34(self, d):
    return _get_or_unk(ALLOCA_TYPE, d)





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
      val = self.blob.read_n(size)
    else:
      raise Exception(f"UKNOWN RECORD id:{idx} type:{kind} !")

    return ConfigEntry(idx, kind, size, val)


  def parse(self, verbose=False):
    self.records = []
    self.records_by_id = dict()

    while self.blob.available() > 6:
      rec = self.parse_single_record()
      if rec is None:
        break
      self.records.append(rec)
      self.records_by_id[rec.id] = rec
      if verbose:
        print(" PARSED " + rec.short_str())
        print()

    for rec in self.records:
      if verbose:
        print(" ENRICH : " + rec.short_str())
      func = getattr(self, "parse_{0}".format(rec.hex_id), None)
      if func is not None and callable(func):
        rec.parsed = func(rec)
        if verbose:
          print("  VALUE :" + repr(rec.parsed))



def magic_detect_config(binary_data, hint_key = None):

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
    xored = alg.decrypt(binary_data)
    pos = _try_to_find_config(xored)
    if pos is not None:
      #print(" ++ FOUND !")
      return xored[pos:pos+MAX_SIZE]

def _to_json(d):
  import json

  class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
      a = getattr(obj, '_to_json', None)
      if a is not None:
        return a()
      return 'wtf'

  print(json.dumps(d, cls=JSONEncoder))

def _to_yaml(d):
  import yaml
  print(yaml.dump(d,  width=1000, default_flow_style=False ))


def _do_curl(p):
  c2_type = p.safe_get_opt(opt='CFG_BeaconType')
  if c2_type.data not in [0,8]:
    return print("INVALID C2 BEACON TYPE" + str(c2_type))
  scheme = "http"
  if c2_type.data == 8:
    scheme = "https"
  c2_addr, get_path = p.safe_get_opt(opt='CFG_C2Server').parsed.split(",",1)
  if get_path[0] != "/":
    get_path = "/" + get_path

  def _gen_curl(opts, verb, base_path):
    curl_opts = ['curl', '-v', '-k', '-g']
    curl_opts.append(f"'{scheme}://{c2_addr}{base_path}{opts['path']}'")
    curl_opts.append(f" -X {verb}")
    for hdr in opts['headers'].split(HTTP_NEWLINE):
      if len(hdr)>1:
        curl_opts.append(f" -H '{hdr}'")
    if len(opts['body'])>1:
      curl_opts.append(f" -d '{opts['body']} '")
    return curl_opts

  print("## ** FIEST REQUEST ** ")
  cmd = _gen_curl(
    opts = p.safe_get_opt(opt='CFG_HttpGet_Metadata').parsed,
    verb = p.safe_get_opt(opt='CFG_HttpGet_Verb').parsed,
    base_path = get_path
  )

  print('\\\n   '.join(cmd))
  print()



  print("## ** SECOND REQUEST ** ")
  cmd = _gen_curl(
    opts = p.safe_get_opt(opt='CFG_HttpPost_Metadata').parsed,
    verb = p.safe_get_opt(opt='CFG_HttpPost_Verb').parsed,
    base_path = p.safe_get_opt(opt='CFG_HttpPostUri').parsed,
  )

  print(' \\\n   '.join(cmd))
  print()


if __name__ == '__main__':
  # Some stuff copied from https://github.com/Sentinel-One/CobaltStrikeParser.git
  #
  parser = argparse.ArgumentParser(description="Parses CobaltStrike Beacon config tool")
  parser.add_argument("file_path", help="Path to file (config, dump, pe, etc)")
  parser.add_argument("--key" , help="Hex encoded xor key to use", default=None)
  parser.add_argument("--json", help="json output", action="store_true", default=False)
  parser.add_argument("--yaml", help="yaml output", action="store_true", default=False)
  parser.add_argument("--none", help="No output. Just parse", action="store_true", default=False)
  parser.add_argument("--curl", help="Generate CURL requests", action="store_true", default=False)


  args = parser.parse_args()
  raw_data = open(args.file_path, "rb").read()
  bin_conf = magic_detect_config(raw_data, None if args.key is None else int(args.key, 16) )
  parser = CobaltConfigParser(bin_conf)
  parser.parse()

  if args.none:
    print('OK!')
  elif args.curl:
    _do_curl(parser)
  elif args.json:
    _to_json(parser.records)
  elif args.yaml:
    _to_yaml(parser.records)
  else:
    for el in parser.records:
      print(el)


# Next line empty
