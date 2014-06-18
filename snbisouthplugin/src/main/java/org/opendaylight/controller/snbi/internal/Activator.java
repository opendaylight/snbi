package org.opendaylight.controller.snbi.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.felix.dm.Component;
import org.opendaylight.controller.sal.core.ComponentActivatorAbstractBase;

public class Activator extends ComponentActivatorAbstractBase {
    private static final String dbgString = "SNBI:Activator:";
    protected static final Logger log = LoggerFactory
            .getLogger(Activator.class);

    public void init() {
    }

    public void destroy() {
    }

    public Object[] getImplementations() {
        Object[] res = { SnbiInternal.class };
        return res;
    }

    public void configureInstance(Component c, Object imp, String containerName) {
        if (imp.equals(SnbiInternal.class)) {
            // export the services
            // Dictionary<String, String> props = new Hashtable<String,
            // String>();
            // props.put("salListenerName",
            // "Secure_Network_Bootstrap_infrastructure");
            // No services are to be imported as yet.
            // c.setInterface(new String[] {Isnbi.class.getName()}, props);

            // Define exported and used services for PacketHandler component.
            c.setInterface(
                    new String[] { org.eclipse.osgi.framework.console.CommandProvider.class
                            .getName() }, null);
        }
    }
}
