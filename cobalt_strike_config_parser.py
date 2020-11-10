"""
  CobaltStrike config extractor && parser.

  Some stuff copied from https://github.com/Sentinel-One/CobaltStrikeParser.git
"""
import io
import struct
import argparse
import pprint
from Crypto.Cipher import XOR

try:
  import json
except ImportError:
  json = None

try:
  import yaml
except ImportError:
  yaml = None



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


def _bytes_strip(bstr):
  return bstr.strip(b'\x00').decode()


class ConfigEntry():
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
    """ used by JSON converter """
    return self.__dict__

  def short_str(self):
    """ single line representation of record """
    return f"[ ID:{self.id}/{self.hex_id} type:{self.kind} size:{self.size:<4} name:{self.name} ]"

  def __str__(self):
    """ return printable representation """
    def _try_to_str(bstr):
      try:
        return _bytes_strip(bstr)
      except Exception:
        return str(bstr)
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


class CobaltConfigParser():
  """
    Parse & store config
  """

  def __init__(self, blob):
    self.blob = BinStream(blob)
    self.records = []
    self.records_by_id = dict()

  def safe_get_opt(self, idx=None, opt=None):
    """ get record by id, softfail """
    if idx is None:
      idx = OPT_TO_ID[opt]
    return self.records_by_id.get(idx, None)

  def parse_0x01(self, rec):
    """ beacon type """
    return BEACON_TYPE.get(rec.data, _UNKNOWN)

  def parse_0x0B(self, rec):
    """ junk """
    stream = BinStream(rec.data)
    retval = []
    cmd = 'data'
    min_bytes = 0
    while stream.available()>1:
      oper = stream.read_4b()
      descr = f" [{oper:08X}] "
      if not oper:
        break
      if oper == 1:
        val = stream.read_4b()
        descr += f"Remove {val} bytes from the end"
        cmd = f"{cmd}[:-{val}]"
        min_bytes += val
      elif oper == 2:
        val = stream.read_4b()
        descr += f"Remove {val} bytes from the beginning"
        cmd = f"{cmd}[{val}:]"
        min_bytes += val
      elif oper == 3:
        descr += "Base64 decode"
        cmd = f"b64decode({cmd})"
      elif oper == 4:
        descr += "NOPE"
      elif oper == 8:
        descr += "decode nibbles 'a'"
        cmd = f"netbios_decode({cmd},ord('a'))"
      elif oper == 11:
        descr += "decode nibbles 'A'"
        cmd = f"netbios_decode({cmd},ord('A'))"
      elif oper == 13:
        descr += "Base64 URL-safe decode"
        cmd = f"b64decode_urlsafe({cmd})"
      elif oper == 15:
        descr += "XOR mask w/ random key"
        cmd = f"dexor({cmd})"
      retval.append(descr)
    return dict(algo=retval, code=cmd, minimal_size=min_bytes)

  def parse_0x2E(self, rec):
    """ code prefix/sufix """
    data = BinStream(rec.data)
    size = data.read_4b()
    prep_val = data.read_n(size)
    size = data.read_4b()
    appe_val = data.read_n(size)
    return dict(prepend = prep_val.hex(), append = appe_val.hex())

  parse_0x2F = parse_0x2E

  def parse_0x0C(self, rec):
    """ HTTP metadata """
    stream = BinStream(rec.data)
    opts = dict(
      headers = '',
      path = '',
      body = '',
    )
    code = []
    tmp_buf = ""

    _path_not_empty = lambda : len(opts['path'])>1
    _read_len_value = lambda x: x.read_n(x.read_4b()).decode()

    while stream.available()>4:
      #print("   BUFFERS ", tmp1,"   #  ",tmp_buf)
      oper = stream.read_4b()
      op_str = f"[{oper:02X}] "
      #print(" OP:",op, d.data[s.tell():][:20] )
      host_entry = self.safe_get_opt(opt='CFG_HostHeader')
      host_str = _bytes_strip(host_entry.data)
      if oper == 0:
        if len(host_str)>1:
          opts['headers'] += host_str + HTTP_NEWLINE
        break
      elif oper == 1:
        value = _read_len_value(stream)
        tmp_buf = tmp_buf + value
        op_str += f"append {value} to tmp_buf"
      elif oper == 2:
        value = _read_len_value(stream)
        tmp_buf = value + tmp_buf
        op_str += f"prepend {value} to tmp_buf"
      elif oper == 3:
        tmp_buf = f"BASE64({tmp_buf})"
        op_str += " BASE64(tmp_buf)"
      elif oper == 4:
        opts['body'] = tmp_buf
        op_str += f"set BODY to tmp_buf: {tmp_buf}"
      elif oper == 5:
        value = _read_len_value(stream)
        if _path_not_empty():
          opts['path'] = f"{opts['path']}&{value}={tmp_buf}"
        else:
          opts['path'] = f"?{value}={tmp_buf}"
        op_str += f"add GET PARAM from tmp_buf : {value}={tmp_buf}"
      elif oper == 6:
        value = _read_len_value(stream)
        hdr = f"{value}: {tmp_buf}"
        opts['headers'] = opts['headers'] + hdr + HTTP_NEWLINE
        op_str += f"add header from TMPtmp_buf2 => {value} : {tmp_buf}"
      elif oper == 7:
        value = stream.read_4b()
        tmp_buf = f"<DATA:{value}>"
        op_str += f"load {tmp_buf} to tmp_buf"
      elif oper == 8:
        tmp_buf = f"<LOWER-CASE_ENCODE({tmp_buf})>"
        op_str += "lower-case encode tmp_buf"
      elif oper == 9:
        value = _read_len_value(stream)
        if _path_not_empty():
          opts['path']= f"{opts['path']}&{value}"
        else:
          opts['path'] = f"?{value}"
        op_str += f"add GET PARAM: {value}"
      elif oper == 10:
        value = _read_len_value(stream)
        opts['headers'] = opts['headers'] + value + HTTP_NEWLINE
        op_str += f"ADD HEADER: {value}"
      elif oper == 11:
        tmp_buf = f"<UPPER-CASE_ENCODE({tmp_buf})>"
        op_str += "upper-case encode tmp_buf"
      elif oper == 12:
        opts['path']= f"{opts['path']}{tmp_buf}"
        op_str += "append local_buf to http_path"
      elif oper == 13:
        tmp_buf = f"<BASE64_URL({tmp_buf})>"
        op_str += " BASE64_URLSAFE(tmp_buf)"
      elif oper == 15:
        tmp_buf = f"<XOR4b({tmp_buf})>"
        op_str = "xor_random4b_key(tmp_buf)"
      elif oper == 16:
        val = _read_len_value(stream)
        if len(host_str) > 1:
          opts['headers'] += host_str + HTTP_NEWLINE
        else :
          opts['headers'] += val + HTTP_NEWLINE
        op_str += " add HOST header or {val}"
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

  def parse_0x28(self, rec):
    """ Kill data """
    return "No kill date set!" if rec.data==0 else rec.data

  parse_to_str = lambda a,b: _bytes_strip(b.data)
  parse_0x08 = parse_to_str
  parse_0x09 = parse_to_str
  parse_0x0A = parse_to_str
  parse_0x0F = parse_to_str
  parse_0x1A = parse_to_str
  parse_0x1B = parse_to_str
  parse_0x1D = parse_to_str
  parse_0x1E = parse_to_str

  def parse_0x33(self, rec):
    """ payload execution """
    data = BinStream(rec.data)
    retval = []
    while data.available()>1:
      oper = data.read_one("B")
      cmd = f"[{oper:02X}] "
      if oper == 0:
        break
      # 1, 2, 3, 4, 5 ,8 = from dict
      if oper in (6,7):
        offset = data.read_2b()
        len1 = data.read_4b()
        val1 = _bytes_strip(data.read_n(len1))
        len2 = data.read_4b()
        val2 = _bytes_strip(data.read_n(len2))
        func = "CreateThread" if oper == 6 else "CreateRemoteThread"
        cmd += f"{func}({val1}::{val2} + {offset})"
      else:
        name = EXECUTE_TYPE.get(oper, None)
        cmd += str(name)
      retval.append(cmd)
    return retval

  def parse_0x34(self, rec):
    """ allocation method """
    return ALLOCA_TYPE.get(rec.data, _UNKNOWN)



  def parse_single_record(self):
    """ parse single record """
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
    """ parse binary data """
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
  """ try all the XOR magic to find data looking like config """

  def _is_this_config(data, offset, pattern1, pattern2):
    #offset = 0
    if data[offset : offset+LENGTH_PATTERN_1] != pattern1:
      return False
    offset += LENGTH_PATTERN_1 
    offset += 2 # WORD
    if data[offset : offset+LENGTH_PATTERN_2] != pattern2:
      return False
    return True

  def _try_to_find_config(data, pattern1, pattern2):
    maxi = len(data) - ( LENGTH_PATTERN_1 + LENGTH_PATTERN_2 + 10 )
    i=0
    while i < maxi:
      if _is_this_config(data, i, pattern1, pattern2):
        return i
      i += 1
    return None

  keys = range(0xff) if hint_key is None else [hint_key]

  for xor_key in keys:
    #print(f" >> Try key : {xor_key} / 0x{xor_key:02X}")
    alg = XOR.new(bytes([xor_key]))
    xored1 = alg.encrypt(CONFIG_PATTERN_1)
    xored2 = alg.encrypt(CONFIG_PATTERN_2)
    pos = _try_to_find_config(binary_data, xored1, xored2)
    if pos is not None:
      return alg.decrypt(binary_data[pos:pos+MAX_SIZE])
  return None




# -----------------------
# - PRINTING FUNCTIONS -
# --------------------

FORMATTERS={}
def register_format(name, info):
  """ decorator to register new output format """
  def _wrap1(func):
    FORMATTERS[name] = dict(func=func, info=info)
    return func
  return _wrap1


@register_format("json","JSON output")
def _to_json(config):

  class JSONEncoder(json.JSONEncoder):
    """ hack to parse object """
    def default(self, o):
      attr = getattr(o, '_to_json', None)
      if attr is not None:
        return attr()
      return 'wtf'

  if json is not None:
    print(json.dumps(config.records, cls=JSONEncoder))
  else:
    print("Install JSON fiest ... ")

@register_format("yaml","YAML output")
def _to_yaml(config):
  if yaml is not None:
    print(yaml.dump(config.records,  width=1000, default_flow_style=False ))
  else:
    print("Install YAML first ... ")

def proxy_http_params(func):
  """ call http_prepare w/ proper callback """
  def _proxy_func(conf):
    _http_prepare_params(conf, func)
  return _proxy_func

@register_format("http","Prepare HTTP request body (for burp, etc) ")
@proxy_http_params
def _gen_http_request(scheme, c2_addr, verb, metadata, base_path, agent):
  print(f" ---- REQUEST {scheme} ---- ")
  out = []
  out.append(f"{verb} {base_path}{metadata['path']} HTTP/1.1")
  if "Host" not in metadata['headers']:
    out.append(f"Host: {c2_addr}")
  for hdr in metadata['headers'].split(HTTP_NEWLINE):
    if len(hdr)>1:
      out.append(f"{hdr}")
  out.append(f"User-Agent: {agent}")

  if len(metadata['body'])>1:
    out.append("Content-length: <fix-content-length>")
    out.append('')
    out.append(f"{metadata['body']}")
  print("\n".join(out))
  print("")
  print(" ------ / -------- ")

@register_format("curl","Craft CURL requests to c2")
@proxy_http_params
def _gen_curl(scheme, c2_addr, verb, metadata, base_path, agent):
  curl_opts = ['curl', '-v -k -g']
  curl_opts.append(f"'{scheme}://{c2_addr}{base_path}{metadata['path']}'")
  curl_opts.append(f" -X {verb}")
  curl_opts.append(f" -A \"{agent}\" ")
  for hdr in metadata['headers'].split(HTTP_NEWLINE):
    if len(hdr)>1:
      curl_opts.append(f" -H '{hdr}'")
  if len(metadata['body'])>1:
    curl_opts.append(f" -d '{metadata['body']} '")
  print("")
  print("  ".join(curl_opts))
  print("")

def _http_prepare_params(conf, calback):
  c2_type = conf.safe_get_opt(opt='CFG_BeaconType')
  if c2_type.data not in [0,8]:
    return print("INVALID C2 BEACON TYPE" + str(c2_type))

  req_params = {}
  req_params['scheme'] = "https" if c2_type.data == 8 else 'http'
  c2_addr, get_path = conf.safe_get_opt(opt='CFG_C2Server').parsed.split(",",1)
  req_params['c2_addr'] = c2_addr
  req_params['agent'] = conf.safe_get_opt(opt='CFG_UserAgent').parsed

  req_params['metadata']  = conf.safe_get_opt(opt='CFG_HttpGet_Metadata').parsed
  req_params['verb']      = conf.safe_get_opt(opt='CFG_HttpGet_Verb').parsed
  req_params['base_path'] = get_path
  calback(**req_params)

  req_params['metadata']  = conf.safe_get_opt(opt='CFG_HttpPost_Metadata').parsed
  req_params['verb']      = conf.safe_get_opt(opt='CFG_HttpPost_Verb').parsed
  req_params['base_path'] = conf.safe_get_opt(opt='CFG_HttpPostUri').parsed
  calback(**req_params)
  return None



@register_format("text","Plain text output")
def _to_text(config):
  for rec in config.records:
    print(rec)

@register_format("none","Print nothing. just parse")
def _no_print(_):
  pass


# -----------------------
# - MAIN --------------
# --------------------

def main():
  """ main function """
  parser = argparse.ArgumentParser(description="Parses CobaltStrike Beacon config tool")
  parser.add_argument("file_path", help="Path to file (config, dump, pe, etc)")
  parser.add_argument("--key" , help="Hex encoded xor key to use", default=None)
  parser.add_argument('--format', help="Use '?' to get list of available formatters",default=None)

  args = parser.parse_args()
  if args.format == '?':
    print("Available formats")
    print('\n'.join(f"- {key} : {val['info']}" for key,val in FORMATTERS.items()))
  else:
    raw_data = open(args.file_path, "rb").read()
    bin_conf = magic_detect_config(raw_data, None if args.key is None else int(args.key, 16) )
    config = CobaltConfigParser(bin_conf)
    config.parse()

    if args.format is not None:
      entry = FORMATTERS.get(args.format)
      if entry is not None:
        entry['func'](config)

if __name__ == '__main__':
  main()
# Next line empty
