import argparse
import struct
import io

def unpack(args):
    order = '<I'
    packed_payload = args.input
    packed_payload = packed_payload.read()
    unpacked_payload = io.BytesIO()
    offset = packed_payload.find(b'\xff\xff\xff') + 3

    key = struct.unpack_from(order, packed_payload, offset)[0]
    size = (struct.unpack_from(order, packed_payload, offset + 4)[0]) 
    size = size ^ key
    mz = struct.unpack_from(order, packed_payload, offset + 8)[0] ^ key
    mz = mz & 0xffff
    unpacked_payload.write(struct.pack(order, mz))
    for i in range(2 + offset // 4, len(packed_payload) // 4 - 4):
        a = struct.unpack_from(order, packed_payload, i * 4)[0]
        b = struct.unpack_from(order, packed_payload, i * 4 + 4)[0]
        out = a ^ b
        unpacked_payload.write(struct.pack(order, out))
    return unpacked_payload

def save_to_disk(payload, args):
   
    with open(args.output,'wb') as fout:
                    fout.write(payload.getvalue())

def main():
  """ main function """
  parser = argparse.ArgumentParser(description="unpack Cobalt Strike beacon to DLL format")

  parser.add_argument('-i', '--input', type=argparse.FileType('rb'),
                      help='Input is packed binary payload of Cobalt Strike beacon that was either grabbed from TeamServer or intercepted on the network', required=True)
  parser.add_argument('-o', '--output', default='beacon.dll',
                      help='Output file is unpacked beacon DLL')
 
  args = parser.parse_args()

  payload  = unpack(args)
  save_to_disk(payload,args)

if __name__ == '__main__':
    main()