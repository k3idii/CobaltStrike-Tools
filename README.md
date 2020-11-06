# CobaltStrikeConfigParser
Parser (and extractor) for CobaltStrike config.

## Usage
```
usage: cobalt_strike_config_parser.py [-h] [--key KEY] [--format FORMAT] file_path

Parses CobaltStrike Beacon config tool

positional arguments:
  file_path        Path to file (config, dump, pe, etc)

optional arguments:
  -h, --help       show this help message and exit
  --key KEY        Hex encoded xor key to use
  --format FORMAT  Use '?' to get list of available formatters


>python cobalt_strike_config_parser.py x --format ?
Available formats
- json : JSON output
- yaml : YAML output
- http : Prepare HTTP request body (for burp, etc) 
- curl : Craft CURL requests to c2
- text : Plain text output
- none : Print nothing. just parse

```

## Example output: 

```
#python cobalt_strike_config_parser.py pe32  --format text | head
[ ID:1/0x01 type:1 size:2    name:CFG_BeaconType ]
  'HTTP'

[ ID:2/0x02 type:1 size:2    name:CFG_Port ]
  80

[ ID:3/0x03 type:2 size:4    name:CFG_SleepTime ]
  60000
```


```
#python cobalt_strike_config_parser.py pe32  --format json | jq . | head
[
  {
    "id": 1,
    "hex_id": "0x01",
    "name": "CFG_BeaconType",
    "kind": 1,
    "size": 2,
    "data": 0,
    "parsed": "HTTP"
  },

```

