"""
  CobaltStrike config extractor && parser.

  Some stuff copied from https://github.com/Sentinel-One/CobaltStrikeParser.git
"""

import argparse
import pprint
from enum import Enum
from Crypto.Cipher import XOR

try:
  import json
except ImportError:
  json = None

try:
  import yaml
except ImportError:
  yaml = None

try:
  from minidump.minidumpfile import MinidumpFile
except ImportError:
  MinidumpFile = None

from bytes_utils import BinStream, AlmostLikeYara, NOT_FOUND, SIZE_DWORD
#, netbios_decode, netbios_encode
import cobalt_const as CobaltConst


HTTP_NEWLINE = "\r\n"

_UNKNOWN = "!UNKNOW!"

class FileFormat(Enum):
  """ supported file types """
  BINARY = 'bin'
  MINIDUMP = 'minidump'

class SearchMode(Enum):
  """ config search modes """
  PACKED='p'
  UNPACKED='u'
  ALL='a'

def _bytes_strip(bstr):
  return bstr.strip(b'\x00').decode()

def _as_c_string(data):
  val = data[:data.find(b"\x00")]
  if len(val) == 0:
    return ''
  return val.decode()


class ConfigEntry():
  """
    Store single config entry
  """
  def __init__(self, idx, kind, size, data):
    self.idx = idx
    self.hex_id = f"0x{idx:02X}"
    self.name = CobaltConst.ID_TO_OPT.get(idx, _UNKNOWN)
    self.kind = kind
    self.size = size
    self.data = data
    self.parsed = None

  def _to_json(self):
    """ used by JSON converter """
    return self.__dict__

  def short_str(self):
    """ single line representation of record """
    return f"[ ID:{self.idx}/{self.hex_id} type:{self.kind} size:{self.size:<4} name:{self.name} ]"

  def __str__(self):
    """ return printable representation """
    def _try_to_str(bstr):
      try:
        return _bytes_strip(bstr)
      except UnicodeDecodeError:
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

  def __init__(self, data_provider, mode):
    self.data_provider = data_provider
    self.mode = mode
    self.records = []
    self.records_by_id = dict()

  def safe_get_opt(self, idx=None, opt=None, default=None):
    """ get record by id, softfail """
    if idx is None:
      idx = CobaltConst.OPT_TO_ID[opt]
    return self.records_by_id.get(idx, default)

  def parse_0x01(self, rec):
    """ beacon type """
    return "[0x{0:04X}] {1}".format(rec.data, CobaltConst.BEACON_TYPE.get(rec.data, _UNKNOWN))

  def parse_0x0B(self, rec):
    """ junk """
    stream = BinStream(rec.data)
    retval = []
    cmd = 'data'
    min_bytes = 0
    while stream.available()>1:
      oper = stream.read_n_dword()
      descr = f" [{oper:08X}] "
      if not oper:
        break
      if oper == 1:
        val = stream.read_n_dword()
        descr += f"Remove {val} bytes from the end"
        cmd = f"{cmd}[:-{val}]"
        min_bytes += val
      elif oper == 2:
        val = stream.read_n_dword()
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
    size = data.read_n_dword()
    prep_val = data.read_n(size)
    size = data.read_n_dword()
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
    _read_len_value = lambda x: x.read_n(x.read_n_dword()).decode()
    host_entry = self.safe_get_opt(opt='CFG_HostHeader')
    host_str = ''
    if host_entry is not None:
      host_str = _as_c_string(host_entry.data)
    #print(host_str)

    while stream.available()>4:
      #print("   BUFFERS ", tmp1,"   #  ",tmp_buf)
      oper = stream.read_n_dword()
      op_str = f"[{oper:02X}] "
      #print(" OP:",op, d.data[s.tell():][:20] )
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
        value = stream.read_n_dword()
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

  _rec_as_c_string = lambda self, rec: _as_c_string(rec.data)
  parse_0x08 = _rec_as_c_string
  parse_0x09 = _rec_as_c_string
  parse_0x0A = _rec_as_c_string
  parse_0x0F = _rec_as_c_string
  parse_0x1A = _rec_as_c_string
  parse_0x1B = _rec_as_c_string
  parse_0x1D = _rec_as_c_string
  parse_0x1E = _rec_as_c_string

  def parse_0x33(self, rec):
    """ payload execution """
    data = BinStream(rec.data)
    retval = []
    while data.available()>1:
      oper = data.read_byte()
      cmd = f"[{oper:02X}] "
      if oper == 0:
        break
      # 1, 2, 3, 4, 5 ,8 = from dict
      if oper in (6,7):
        offset = data.read_n_word()
        len1 = data.read_n_dword()
        val1 = _bytes_strip(data.read_n(len1))
        len2 = data.read_n_dword()
        val2 = _bytes_strip(data.read_n(len2))
        func = "CreateThread" if oper == 6 else "CreateRemoteThread"
        cmd += f"{func}({val1}::{val2} + {offset})"
      else:
        name = CobaltConst.EXECUTE_TYPE.get(oper, None)
        cmd += str(name)
      retval.append(cmd)
    return retval

  def parse_0x34(self, rec):
    """ allocation method """
    return CobaltConst.ALLOCA_TYPE.get(rec.data, _UNKNOWN)



  def _read_single_packed_record(self, source):
    """ parse single record """
    idx  = source.read_n_word()
    if idx == 0:
      return None
    kind = source.read_n_word()
    size = source.read_n_word()
    val  = None
    if kind == 1:
      val = source.read_n_word()
    elif kind == 2:
      val = source.read_n_dword()
    elif kind == 3:
      val = source.read_n(size)
    else:
      raise Exception(f"UKNOWN RECORD id:{idx} type:{kind} !")

    return ConfigEntry(idx, kind, size, val)

  def _add_record(self, rec):
    self.records.append(rec)
    self.records_by_id[rec.idx] = rec

  def _parse_packed(self, verbose=False):
    source = BinStream(
      self.data_provider.read(
        self.data_provider.found_at, CobaltConst.MAX_SIZE
      )
    )
    while source.available() > 6:
      rec = self._read_single_packed_record(source)
      if rec is None:
        break
      self._add_record(rec)
      if verbose:
        print(" PARSED " + rec.short_str())
        print()

  def _parse_unpacked(self, verbose=False):
    data = self.data_provider.read(
        where = self.data_provider.found_at,
        how_many = SIZE_DWORD * 2 * (CobaltConst.MAX_ID+2)
    )
    #print(data)
    source = BinStream(data)
    self.records = []
    source.read_n(2 * SIZE_DWORD) # 2x null
    for i in range(1,CobaltConst.MAX_ID):
      kind = source.read_h_dword()
      value = source.read_h_dword()
      if kind == 3:
        if verbose:
          print("Try to read ptr")
        blob = self.data_provider.read(value, CobaltConst.MAX_REC_SIZE)
        value = blob
      rec = ConfigEntry(i, kind, 0, value)
      #print(rec)
      self._add_record(rec)

  def parse(self, verbose=False):
    """ parse binary data """
    #verbose = 1
    self.records = []
    self.records_by_id = dict()
    if self.mode == SearchMode.PACKED:
      self._parse_packed(verbose)
    if self.mode == SearchMode.UNPACKED:
      self._parse_unpacked(verbose)

    for rec in self.records:
      if verbose:
        print(" ENRICH : " + rec.short_str())
      func = getattr(self, "parse_{0}".format(rec.hex_id), lambda x:None)
      if func and callable(func):
        rec.parsed = func(rec)
        if verbose:
          print("  VALUE :" + repr(rec.parsed))
          #print(rec)

class BinaryInterface:
  """ Interface to flat binary file """
    ## TODO: implement buffered reader/mapFIle for large flat files ?
  def __init__(self, filename):
    self.filename = filename
    self.data = open(filename,'rb').read()
    self.found_at = NOT_FOUND
    self.encoder = None

  def find_using_func(self, func):
    """ find using callback, feed w/ data """
    result = func(self.data)
    self.found_at = result
    return result

  def read(self, where, how_many):
    """ read ( address, size ) """
    blob = self.data[where:where+how_many]
    if self.encoder is not None:
      blob = self.encoder(blob)
    return blob

class MinidumpInterface:
  """ interface for minidump file format """
  def __init__(self, filename):
    self.filename = filename
    self.obj = MinidumpFile.parse(filename)
    self.reader = self.obj.get_reader()
    self.found_at = NOT_FOUND
    self.encoder = None


  def find_using_func(self, func):
    """ find using callback, feed w/ data """
    for seg in self.reader.memory_segments:
      blob = seg.read(seg.start_virtual_address, seg.size, self.reader.file_handle)
      result = func(blob)
      if result != NOT_FOUND:
        self.found_at = result + seg.start_virtual_address
        return result
    return NOT_FOUND

  def read(self, where, how_many):
    """ read ( address, size ) """
    return self.reader.read(where, how_many)


def try_to_find_config(filename, file_type=FileFormat.BINARY, mode=SearchMode.ALL, hint_key=None):
  """ try all the XOR magic to find data looking like config """

  data_provider = None
  if file_type == FileFormat.BINARY:
    data_provider = BinaryInterface(filename)
  if file_type == FileFormat.MINIDUMP:
    if MinidumpFile is None:
      raise Exception("Need to have working minidump module !")
    data_provider = MinidumpInterface(filename)

  if mode in (SearchMode.PACKED, SearchMode.ALL):
    #rint("MODE PACKED")
    keys_to_test = range(0xff) if hint_key is None else [hint_key]
    for cur_key in keys_to_test:
      #print("KEY = ", key)
      _xor_array = lambda arr, key=cur_key: XOR.new(bytes([key])).encrypt(arr)
      finder = AlmostLikeYara(CobaltConst.PACKED_CONFIG_PATTERN, encoder=_xor_array)
      result = data_provider.find_using_func(finder.smart_search)
      if result != NOT_FOUND:
        data_provider.encoder = _xor_array
        #print("FOUND PACKED @ ", result)
        return data_provider, SearchMode.PACKED

  if mode in (SearchMode.UNPACKED, SearchMode.ALL):
    finder = AlmostLikeYara(CobaltConst.UNPACKED_CONFIG_PATTERN)
    result = data_provider.find_using_func(finder.smart_search)
    if result != NOT_FOUND:
      return data_provider, SearchMode.UNPACKED

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

@register_format('request','Try to make HTTP request to c2')
@proxy_http_params
def _gen_reqest(*_):
  print("Work in progress :-)")


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
  for rec in sorted(config.records, key=lambda rec: rec.idx):
    print(rec)

DEFAULT_OUTPUT = 'none'
@register_format("none","Print nothing. just parse")
def _no_print(_):
  pass

# -----------------------
# - MAIN --------------
# --------------------


def main():
  """ main function """
  parser = argparse.ArgumentParser(
    description="""
+--- -                 - ---------+
| CobaltStrike Beacon config tool |
+------- -                    ----+ 
    """,
    epilog = "Available output formats: \n" + "\n".join(
      f"- {key:5} : {val['info']}"  for key,val in FORMATTERS.items()
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter
  )
  parser.add_argument(
    "file_path",
    help="Path to file (config, dump, pe, etc)"
  )
## TODO: add ability to attach to process and just RIP the memory :-)
  parser.add_argument(
    "--ftype",
    help="Input file type. Default=raw",
    choices=[x.value for x in FileFormat],
    #type=FileFormat,
    default=FileFormat.BINARY,
  )
  parser.add_argument(
    "--key",
    help="Hex encoded, 1 byte xor key to use when doing xor-search",
    default=None
  )
  parser.add_argument(
    '--mode',
    help='Search for [p]acked or [u]npacked or try [a]ll config. Default=[a]ll',
    choices=[x.value for x in SearchMode],
    default=SearchMode.ALL,
  )
  parser.add_argument(
    '--format',
    help="Output format",
    choices=FORMATTERS.keys(),
    default=DEFAULT_OUTPUT,
    required=True
  )

  args = parser.parse_args()
  args.mode = SearchMode(args.mode)
  args.ftype = FileFormat(args.ftype)

  result = try_to_find_config(
    args.file_path, hint_key=args.key,
    file_type=args.ftype, mode=args.mode
  )
  if result is None:
    print("FAIL TO FIND CONFIG !")
    return
  file_obj, mode = result
  config = CobaltConfigParser(file_obj, mode=mode)
  config.parse()

  if args.format is not None:
    entry = FORMATTERS.get(args.format)
    if entry is not None:
      entry['func'](config)

if __name__ == '__main__':
  main()
# Next line empty
