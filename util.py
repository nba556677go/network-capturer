import subprocess
import json
import codecs

def redPrint(*argv):
  print('\033[91m'+" ".join(str(ele) for ele in argv)+'\033[0m')

def greenPrint(*argv):
  print('\033[92m'+" ".join(str(ele) for ele in argv)+'\033[0m')

def load_config(filename, var="SUBNET"):
  try:
    configs = {}
    with open(filename, 'r') as infile:
      for line in infile:
        pair = line.split("=")
        configs[pair[0]] = pair[1]
    return configs[var]
  except:
    redPrint("[!] Load config error")
    exit()

def parse_ip(ip):
  try:
    nums = ip.split('.')
    return sum([int(nums[i])*(256**(3-i)) for i in range(4)])
  except:
    redPrint("[!] Parse IP error! IP:", ip)

def in_subnet(host, subnet):
  host = parse_ip(host)
  l = subnet.split('/')
  prefix, mask = parse_ip(l[0]), int(l[1])
  mask = ((1 << mask) - 1)*(2**(32-mask))
  return (host & mask) == (prefix & mask)

def findnth(string, substring, n):
  parts = string.split(substring, n + 1)
  if len(parts) <= n + 1:
    return -1
  return len(string) - len(parts[-1]) - len(substring)

def follow_stream(protocol , streamID , pcapfile):
  raw = subprocess.check_output(f"tshark -r {pcapfile} -Y usb -z follow,{protocol},ascii,{streamID} ",  shell=True)
  raw = raw[findnth(raw ,b'\n', 5 )+1 :raw.rfind(b'\n' , 0,len(raw) - 1)]
  return raw

def hex_handler(err):
    thebyte = err.object[err.start:err.end]
    repl = u'\\x'+hex(ord(thebyte))[2:]
    return (repl, err.end)

def to_sessions(tcp, udp):
  sessions = [session for session in tcp.values()] + [session for session in udp.values()]
  for session in sessions: 
    del session['packet_ids']
    # To epoch millis
    session['timestamp'] = str(round(float(session['timestamp'])*1000))
    # Bytes to str
    session['payload'] = session['payload'].decode('utf-8', 'hex_handler')
    session['payload_length'] = len(session['payload'])
  return sessions

codecs.register_error('slashescape', hex_handler)
def writejson(sessions, filename):
  with open(filename, 'w') as outfile: 
    json.dump(sessions, outfile)