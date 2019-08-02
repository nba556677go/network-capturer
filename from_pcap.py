import pyshark
from util import *
from send import send_array, send_json
import sys

out, es, debug = None, None, False
def parse_args(args):
  global out, es, debug
  for i in range(2,len(args)):
    if args[i] == "-out":
      if i == len(args)-1: return False
      out = args[i+1]
    elif args[i] == "-es":
      if i == len(args)-1: return False
      es = args[i+1]
    elif args[i] == "--debug": debug = True
  if out is None and es is None:
    return False
  return True

if len(sys.argv) < 4 or not parse_args(sys.argv):
  print("Usage: python3 from_pcap.py <input file> [-out output_file] [-es Elasticsearch_URI] [--debug]")
  exit(1)

pcapfile = sys.argv[1]
subnet = load_config("./subnet.config")
tcp_sessions = {}
udp_sessions = {}
first_udp = {}

if debug: print("[*] Reading pcap file...")
packets = pyshark.FileCapture( pcapfile , display_filter="ip && (tcp || udp)")

if debug: print("[*] Parsing sessions...")
i = 0
for packet in packets:
  if 'TCP' in packet:
    # Session beign
    if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1' and in_subnet(packet.ip.src, subnet) and not in_subnet(packet.ip.dst, subnet):
      tcp_sessions[packet.tcp.stream] = {
        'client': packet.ip.dst,
        'server': packet.ip.src,
        'client_port': packet.tcp.dstport,
        'server_port': packet.tcp.srcport,
        'protocol' : packet.highest_layer,
        'transport_layer_protocol': "TCP",
        'timestamp' : packet.sniff_timestamp,
        'packet_ids': [i]
      }
    elif packet.tcp.stream in tcp_sessions:
      tcp_sessions[packet.tcp.stream]['packet_ids'].append(i)
      if packet.highest_layer != 'TCP' and tcp_sessions[packet.tcp.stream]['protocol'] == 'TCP':
        tcp_sessions[packet.tcp.stream]['protocol'] = packet.highest_layer
  elif 'UDP' in packet:
    first = False
    if packet.udp.stream not in first_udp:
      first_udp[packet.udp.stream] = i
      first = True
    if packet.udp.stream not in udp_sessions and first and not in_subnet(packet.ip.src, subnet) and in_subnet(packet.ip.dst, subnet):
      udp_sessions[packet.udp.stream] = {
        'client': packet.ip.src,
        'server': packet.ip.dst,
        'client_port': packet.udp.srcport,
        'server_port': packet.udp.dstport,
        'protocol' : packet.highest_layer,
        'transport_layer_protocol': "UDP",
        'timestamp' : packet.sniff_timestamp,
        'packet_ids': [i]
      }
    elif packet.udp.stream in udp_sessions:
      try:
        udp_sessions[packet.udp.stream]['packet_ids'].append(i)
        if packet.highest_layer != 'UDP' and udp_sessions[packet.udp.stream]['protocol'] == 'UDP':
          udp_sessions[packet.udp.stream]['protocol'] = packet.highest_layer
      except:
        print("[!] Handle UDP datagram error:", udp_sessions, packet.udp.stream)
        exit(1)
  i += 1

if debug: print("[*] Adding payload info...")
#process payload
for streamID in tcp_sessions.keys():
  payload = follow_stream("tcp",streamID, pcapfile)
  tcp_sessions[streamID]['payload'] = payload

for streamID in udp_sessions.keys():
  payload = follow_stream("udp",streamID, pcapfile) 
  udp_sessions[streamID]['payload'] = payload

sessions = to_sessions(tcp_sessions, udp_sessions)
if out is not None:
  writejson(sessions, out)
if es is not None:
  send_array(es, sessions, debug)