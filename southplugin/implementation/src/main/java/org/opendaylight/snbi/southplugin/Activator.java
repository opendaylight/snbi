package org.opendaylight.snbi.southplugin;

import org.opendaylight.controller.sal.binding.api.AbstractBindingAwareProvider;
import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.ProviderContext;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Activator class following the new MD-SAL path
public class Activator extends AbstractBindingAwareProvider {
    protected static final Logger logger = LoggerFactory
            .getLogger(Activator.class);

    // called during osgi start
    @Override
    public void onSessionInitiated(final ProviderContext session) {
        logger.info("Initializing SNBI South Plugin Activator");
    }

    // called durng osgi stop
    @Override
    protected void stopImpl(final BundleContext context) {
        logger.info("SNBI South Plugin Activator clean up completed ");
    }

}
