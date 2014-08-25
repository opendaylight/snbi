package org.opendaylight.snbi.southplugin;

public class eventContext {
    enum eventType {
        PKT_EVENT;
    }
   
    SnbiPkt pkt;
    
    public eventContext (SnbiPkt pkt) {
        this.pkt = pkt;
    }
    
    public SnbiPkt getPkt () {
        return pkt;
    }

}
