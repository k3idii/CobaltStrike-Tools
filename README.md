# CobaltStrikeConfigParser
Parser (and extractor) for CobaltStrike config.

## Usage
```
usage: cobalt_strike_config_parser.py [-h] [--key KEY] [--json] [--yaml] file_path

positional arguments:
  file_path   Path to file (config, dump, pe, etc)

optional arguments:
  -h, --help  show this help message and exit
  --key KEY   Hex encoded xor key to use;  <-- if not provided, all 1b XOR key will be tried
  --json      json output
  --yaml      yaml output
```

## Example output: 

```
#python cobalt_strike_config_parser.py  pe32dump --key 2e 
[ ID:1/0x01 CFG_BeaconType ]
   HTTP

[ ID:2/0x02 CFG_Port ]
   80

[ ID:3/0x03 CFG_SleepTime ]
   60000
```


```
#python cobalt_strike_config_parser.py  pe32dump --json | jq.
[
  {
    "id": 1,
    "hex_id": "0x01",
    "kind": 1,
    "size": 2,
    "name": "CFG_BeaconType",
    "raw_value": 0,
    "parsed_value": "HTTP"
  },
  {
    "id": 2,
    "hex_id": "0x02",
    "kind": 1,
    "size": 2,
    "name": "CFG_Port",
    "raw_value": 80,
    "parsed_value": null
  },
```