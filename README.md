# CobaltStrikeConfigParser
Parser (and extractor) for CobaltStrike config.

## Usage
```
usage: cobalt_strike_config_parser.py [-h] [--ftype {bin,minidump}] [--key KEY] [--mode {p,u,a}] --format {json,yaml,http,curl,request,text,none} file_path

+--- -                        - ---------+
| Parses CobaltStrike Beacon config tool |
+------- -                           ----+ 
    

positional arguments:
  file_path             Path to file (config, dump, pe, etc)

optional arguments:
  -h, --help            show this help message and exit
  --ftype {bin,minidump}
                        Input file type. Default=raw
  --key KEY             Hex encoded, 1 byte xor key to use when doing xor-search
  --mode {p,u,a}        Search for [p]acked or [u]npacked or try [a]all  config. Default=[a]ll
  --format {json,yaml,http,curl,request,text,none}
                        Output format

Available output formats: 
- json  : JSON output
- yaml  : YAML output
- http  : Prepare HTTP request body (for burp, etc) 
- curl  : Craft CURL requests to c2
- request : Try to make HTTP request to c2
- text  : Plain text output
- none  : Print nothing. just parse


```

## Example output: 


### Text output 
```
#python cobalt_strike_config_parser.py pe32  --format text | head | grep ...
[ ID:1/0x01 type:1 size:2    name:CFG_BeaconType ]
  'HTTP'
[ ID:2/0x02 type:1 size:2    name:CFG_Port ]
  80
[ ID:3/0x03 type:2 size:4    name:CFG_SleepTime ]
  60000
```

### Getting config as JSON
```
#python cobalt_strike_config_parser.py  pe32 --format json  | jq . | head
[
  {
    "idx": 1,
    "hex_id": "0x01",
    "name": "CFG_BeaconType",
    "kind": 1,
    "size": 2,
    "data": 0,
    "parsed": "[0x0000] HTTP"
  },
```
### Parsing minidump file 

```
>python cobalt_strike_config_parser.py  runshell1_f2.dmp --ftype minidump --mode u --format text   | head  | grep ...
[ ID:1/0x01 type:1 size:0    name:CFG_BeaconType ]
  '[0x0000] HTTP'
[ ID:2/0x02 type:1 size:0    name:CFG_Port ]
  80
[ ID:3/0x03 type:2 size:0    name:CFG_SleepTime ]
  60000

```

### Getting ready HTTP request 
Ready to be pasted into BURP :-)
```
python cobalt_strike_config_parser.py  pe32 --format http | head
 ---- REQUEST http ---- 
GET /some/get/path HTTP/1.1
Host: c2.hostname.com
Accept: */*
Accept-Language: en-US
Connection: close
Cookie: prov=<LOWER-CASE_ENCODE(<DATA:0>)>;notice-ctt=2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

 ------ / -------- 
```