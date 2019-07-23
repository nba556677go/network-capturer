import pyshark
from util import *
import sys

if len(sys.argv) != 3:
  print("Usage: python3 from_pcap.py <input file> <output file>")
  exit()

pcapfile = sys.argv[1]
subnet = load_config("./subnet.config")
'''
session:
{
  'stream_idx': {
    'src_ip': IP,
    'dst_ip': IP,
    'src_port': PORT,
    'dst_port': PORT,
    'packet_ids': [indexes]
  }
}
'''
tcp_sessions = {}
udp_sessions = {}
first_udp = {}

print("[*] Reading pcap file...")
packets = pyshark.FileCapture( pcapfile , display_filter="ip && (tcp || udp)")

print("[*] Parsing sessions...")
i = 0
for packet in packets:
  if 'TCP' in packet:
    # Session beign
    if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0' and not in_subnet(packet.ip.src, subnet) and in_subnet(packet.ip.dst, subnet):
      #print(packet.sniff_timestamp)
      tcp_sessions[packet.tcp.stream] = {
        'src_ip': packet.ip.src,
        'dst_ip': packet.ip.dst,
        'src_port': packet.tcp.srcport,
        'dst_port': packet.tcp.dstport,
        'protocol' : packet.highest_layer,
        'timestamp' : packet.sniff_timestamp,
        'packet_ids': [i]
      }
    elif packet.tcp.stream in tcp_sessions:
      tcp_sessions[packet.tcp.stream]['packet_ids'].append(i)
  elif 'UDP' in packet:
    first = False
    if packet.udp.stream not in first_udp:
      first_udp[packet.udp.stream] = i
      first = True
    if packet.udp.stream not in udp_sessions and first and not in_subnet(packet.ip.src, subnet) and in_subnet(packet.ip.dst, subnet):
      udp_sessions[packet.udp.stream] = {
        'src_ip': packet.ip.src,
        'dst_ip': packet.ip.dst,
        'src_port': packet.udp.srcport,
        'dst_port': packet.udp.dstport,
        'protocol' : packet.highest_layer,
        'timestamp' : packet.sniff_timestamp,
        'packet_ids': [i]
      }
    elif packet.udp.stream in udp_sessions:
      try:
        udp_sessions[packet.udp.stream]['packet_ids'].append(i)
      except:
        print(udp_sessions, packet.udp.stream)
        exit()
  i += 1

print("[*] Adding payload info...")
#process payload
for streamID in tcp_sessions.keys():
  payload = follow_stream("tcp",streamID, pcapfile)
  tcp_sessions[streamID]['payload'] = payload

for streamID in udp_sessions.keys():
  payload = follow_stream("udp",streamID, pcapfile) 
  udp_sessions[streamID]['payload'] = payload

writejson(tcp_sessions , udp_sessions, sys.argv[2])