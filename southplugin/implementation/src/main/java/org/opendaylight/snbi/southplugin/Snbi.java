package org.opendaylight.snbi.southplugin;

import java.security.InvalidParameterException;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * Provide services to start SNBI in the system.
 *
 */
public class Snbi {
    ConcurrentHashMap <String, SnbiRegistrar> registrarList = null;
//    private static final Logger log = LoggerFactory.getLogger(Snbi.class);

    public Snbi(String domainName) throws InvalidParameterException {
        SnbiRegistrar registrar = null;
        if (domainName == null || domainName.equals(null)
                || (domainName.length() == 0)) {
            throw new InvalidParameterException(domainName
                    + " is not a valid domain name");
        }
        
        if (registrarList == null) {
            registrarList = new ConcurrentHashMap <String, SnbiRegistrar>();
            
        }
        System.out.println("Creating registrar");
        registrar = new SnbiRegistrar(domainName);
        registrarList.put(domainName, registrar);
    }

    public List<SnbiNode> getNeighbors(String domainName) {
        SnbiRegistrar registrar = null;
        
        if (registrarList.containsKey(domainName)) {
            registrar = registrarList.get(domainName);
            return registrar.getNeighborNodes();
        }
        return null;
    }


    protected void finalize () {
    }
}
