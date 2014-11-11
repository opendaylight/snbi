#!/usr/bin/python
#
# SNBI local configuration verifier
#
# Oct, 2014,   Liming Wei
#
# This script looks up the local SNBI datastore, for the
# named portable foundation (PF). If the PF is found, it
# lets the calling bash shell (cpa) set the CNAME environment
# variable to the name of the PF. Else  CNAME is set to string
# "default".
#
import sys, json, os
import host_pf_server

''' Do nothing if accidentally imported by something else. '''
if __name__ != '__main__':
  sys.exit(2)

if len(sys.argv) != 2 :
  print ("Error. Must provide a portable foundation name!")
  sys.exit(0)

cid = str(sys.argv[1])

udi_e = host_pf_server.OdlSnbiServerGetUdi(cid)


if udi_e['container_name'] != sys.argv[1] :
  print ("export CNAME=default")
  sys.exit(1)

print ("export CNAME=%s" % sys.argv[1])

sys.exit(0)
