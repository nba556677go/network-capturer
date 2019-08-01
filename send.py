from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import json
from datetime import datetime
import sys

def gendoc(sessions):
  date = datetime.now()
  index = "services-{}-{}-{}".format(date.year, date.month, date.day)
  for session in sessions:
    yield {
      "_index": index,
      "_type": "_doc",
      **session
    }

def send_json(ip, filename, debug=False):
  sessions = []
  try:
    with open(filename, 'r') as ifile:
      sessions = json.load(ifile)
  except:
    print("[!] Input file error")
    return False

  return send_array(ip, sessions, debug)

def send_array(ip, arr, debug=False):
  try:
    es = Elasticsearch([ip])
  except:
    print("[!] Elasticsearch endpoint connection error")
    return False
  
  if debug: print("[*] Sending session(s)...")
  bulk(es, gendoc(arr))
  if debug: print("[*] {} session(s) sent".format(len(arr)))
  
  return True

if __name__ == "__main__":
  if len(sys.argv) != 3:
    print("Usage: python3 send.py <Elasticsearch URI> <Input File>")
    exit()
  send_json(sys.argv[1], sys.argv[2], True)