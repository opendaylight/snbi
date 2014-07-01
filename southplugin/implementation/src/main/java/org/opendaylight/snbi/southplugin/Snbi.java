package org.opendaylight.snbi.southplugin;

import java.security.InvalidParameterException;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * Provide services to start SNBI in the system.
 *
 */
public class Snbi {
    private String domainName = null;
    private SnbiNeighborDiscovery ndInstance = null;
    private static final Logger log = LoggerFactory.getLogger(Snbi.class);

    public Snbi(String domainName) throws InvalidParameterException {
        if (domainName == null || domainName.equals(null)
                || (domainName.length() == 0)) {
            throw new InvalidParameterException(domainName
                    + " is not a valid domain name");
        }
        this.domainName = domainName;
        this.ndInstance = new SnbiNeighborDiscovery(this);
    }

    public void snbiStart() {
        ndInstance.ndStart();
    }

    /**
     * Get the domain name of the SNBI.
     *
     * @return The domain name of the SNBI.
     */
    public String getDomainName() {
        return this.domainName;
    }

    public List<SnbiNode> getNeighbors() {
        return ndInstance.getNeighborNodes();
    }

    /**
     * Stop SNBI for the current domain.
     *
     * @return <tt>true</tt> if the SNBI process was stopped successfully,
     *         <tt>false</tt> otherwise.
     */
    public boolean snbiStop() {
        ndInstance.ndStop();
        return true;
    }

    protected void finalize () {
        snbiStop();
    }
}
