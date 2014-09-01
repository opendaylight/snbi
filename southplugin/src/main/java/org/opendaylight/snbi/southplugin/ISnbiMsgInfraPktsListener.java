package org.opendaylight.snbi.southplugin;
/**
 * Interface for the messaging service.
 */
interface ISnbiMsgInfraPktsListener {    
    void incomingNDPktsListener (SnbiPkt pkt);
    
    void incomingNICertReqPktsListener (SnbiPkt pkt);
    
    void incomingNICertRespPktsListener (SnbiPkt pkt);
    
    void incomingNbrConnectPktsListener (SnbiPkt pkt);
    
    void incomingBSReqPktsListener (SnbiPkt pkt);

}

