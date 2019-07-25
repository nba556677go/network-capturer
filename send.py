from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import json
import sys

if len(sys.argv) != 3:
  print("Usage: python3 send.py <Elasticsearch URI> <Input File>")
  exit()

def gendoc(sessions):
  for session in sessions:
    yield {
      "_index": "services",
      "_type": "_doc",
      **session
    }

try:
  es = Elasticsearch([sys.argv[1]])
except:
  print("[!] Elasticsearch endpoint connection error")
  exit()

sessions = []
try:
  with open(sys.argv[2], 'r') as ifile:
    sessions = json.load(ifile)
except:
  print("[!] Input file error")
  exit()

print("[*] Sending session(s)...")
bulk(es, gendoc(sessions))
print("[*] {} session(s) sent".format(len(sessions)))