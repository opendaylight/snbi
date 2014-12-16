#
# SNBI RestConf Server running on the machine hosting the containers.
#
# Liming Wei,  Sept 2, 2014
#
# This script reads the Universal Device Identifier (UDI) database
# from file UDI_DB.json. This file is in JSON encoded from UDI_DB.yang.
# Before UDI_DB.yang is created, the relevant portion of the Yang for
# UDI_DB.json is,
#
# list UDI_DB {
#    key container_name;
#    leaf container_name {
#        type string;
#    }
#    leaf UDI {
#        type string;
#    }
#    leaf UUID {
#        type string;
#    }
# }
#
# The following is an example content from the above yang,
# {
#    "UDI_DB": [
#        {
#            "container_name": "SNBI_PF0",
#            "UDI": "6ba7b811-9dad-11d1-80b4-00c04fdaaaaa",
#            "UUID": "6ba7b811-9dad-11d1-80b4-00c04fdaaaaa"
#        },
#        {
#            "container_name": "default",
#            "UDI": "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
#            "UUID": "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
#        }
#    ]
# }
#
# Example, GET query from client has path of
# http://127.0.0.1:8080/restconf/data/SNBI:udi/UDI?cid=SNBI_PF1

import json

import cherrypy


def OdlSnbiServerGetUdi(container_name):
    """Obtain the UDI element of container_name, if container_name

    If not found in UDI_DB, return the default bad ID
    """
    f = open('UDI_DB.json', 'r')
    t = f.read()
    # Decode the JSON string into python data
    py = json.loads(t)
    arr = py['UDI_DB']
    f.close()

    # Find container_name in arr
    for x in arr:
        # print ("Name is %s, UDI is %s" % (x['container_name'], x['UDI']))
        if (x['container_name'] == container_name):
            return x
    return arr[-1]


class Root(object):
    @cherrypy.expose
    def index(self):
        return ("This is the SNBI container config server. "
                "Please provide a valid path.")

    index.exposed = True

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def UDI(self, cid="default"):
        udi_e = OdlSnbiServerGetUdi(cid)
        udi = {'UDI_DB': udi_e}
        udi_json = json.dumps(udi)
        cherrypy.response.headers['Content-Type'] = "application/json"
        return udi_json

    UDI.exposed = True

import os.path
tutconf = os.path.join(os.path.dirname(__file__), 'tutorial.conf')

if __name__ == '__main__':
    cherrypy.quickstart(Root(), '/restconf/data/SNBI:udi/', config=tutconf)
