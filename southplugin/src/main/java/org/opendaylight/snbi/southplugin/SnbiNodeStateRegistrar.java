package org.opendaylight.snbi.southplugin;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiNodeStateRegistrar extends SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {
    private static final Logger log = LoggerFactory.getLogger(SnbiNodeStateRegistrar.class);

    public SnbiNodeStateRegistrar(SnbiNode node) {
        super(node);
    }
    
    @Override
    public SnbiNodeState getState() {
        return SnbiNodeState.SNBI_NODE_STATE_REGISTRAR;
    }
    
    @Override
    public SnbiNodeState nodeStateSetEvent(eventContext evt) {
        log.debug("[node: "+node.getUDI()+"] Set state : "+this.getState());
        node.getRegistrar().validateNode(node);
        bootStrapSelf();
        node.ndStart();
        return node.getCurrState();
    }
    
    private void bootStrapSelf () {
        PKCS10CertificationRequest pkcs10CSR = null;
        try {
        pkcs10CSR = CertManager.getInstance().generateCSRRequest(node.getDeviceID(), 
                                                            node.getRegistrar().getDomainName(), 
                                                            node.getUDI());
        } catch (Exception excpt) {
            log.error("Encountered exception while generating CSR request "+excpt);
        }
        
        
        try {
            node.SetCertificate(CertManager.getInstance().generateX509Certificate(pkcs10CSR, null));
        } catch (Exception excpt) {
            log.error(" Encountered exception while generating X509 cert" +excpt);
        }
        log.debug(" UDI is "+node.getUDI());        
        CertificateMgmt.printCertificate(node.getCertificate());
        node.setBootStrapped(true);
    }
     
    @Override    
    public SnbiNodeState handleNodeExpiredEvent () {
        log.debug("[node: "+node.getUDI()+"] Handle Node Expired Event");
        return node.getCurrState();
    }
}
