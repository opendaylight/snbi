/*
 * Copyright (c) 2014 Ericsson Systems, Inc. and others.  All rights reserved.
 * Anu Nair
 * anu.nair@ericsson.com
 */

package org.opendaylight.snbi.certmgmt;

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
        // start the certificate manager initialization
        logger.info("Initializing SNBI Activator");
        CertManager.INSTANCE.start();
        logger.info("SNBI Activator initialization completed ");
    }

    // called durng osgi stop
    @Override
    protected void stopImpl(final BundleContext context) {
        logger.info("SNBI Activator clean up completed ");
    }

}
