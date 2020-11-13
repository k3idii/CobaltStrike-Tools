
rule CobaltStrike_inMemory_config
{
    strings:
        $hex_string = {
  00 00 00 00   00 00 00 00 
  01 00 00 00   (00|01|02|04|08|0A) 00 00 00
  01 00 00 00   ?? ?? 00 00
  02 00 00 00   ?? ?? ?? ??
  02 00 00 00   ?? ?? ?? ??
  01 00 00 00   ?? ?? 00 00
  01 00 00 00   
        }
    condition:
        $hex_string
}


