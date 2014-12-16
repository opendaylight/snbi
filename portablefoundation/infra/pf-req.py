#!/usr/bin/python
# pf-req.py
#
# Sep 5, 2014  Liming Wei
#
# A reference client that obtains the UDI of the current container
# from the hosting environment for the container, and writes the
# local container's UDI into the file my_udi.
#
# The current container's name, or "client ID" (such as SNBI_PF0,
# SNBI_PF1, SNBI_CTRL, etc) is stored in the environment variable CID.
#
import json
import os
import time

import requests


#
# If YANG model changed, for which a YANG tool automatically generates
# a new API, replace the following with the newly generated one,
#
PF_HOST_API_PATH = '/restconf/data/SNBI:udi/'

cid = os.getenv('CID', 'default')
r = requests.get('http://127.0.0.1:8080' + PF_HOST_API_PATH + 'UDI?cid=' + cid)
j = json.loads(r.json())

f = open('/home/snbi/my_udi', 'w')
f.write(json.dumps(j, sort_keys=True, indent=4, separators=(',', ': ')))
f.flush()
f.close()

#
# Pretend we are a long lived daemon.
#
while 1:
    time.sleep(1000)
