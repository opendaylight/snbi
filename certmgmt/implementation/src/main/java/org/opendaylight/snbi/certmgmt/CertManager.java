/*
 * Copyright (c) 2014 Ericsson Systems, Inc. and others.  All rights reserved.
 * Anu Nair
 * anu.nair@ericsson.com
 */

package org.opendaylight.snbi.certmgmt;

import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Singleton instance for certificate manager
 */
public enum CertManager implements ICertManager {
    INSTANCE;
    private static final Logger logger = LoggerFactory.getLogger(CertManager.class);

    // Start method called by Activator
    // Initialize the SNBI registrar
    void start() {
        logger.info(" CertManager::Starting");
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
        bundleContext.registerService(CertManager.class.getName(), this, null);
        SNBIRegistrar.INSTANCE.init();
    }

    void stop() {
        // to do later for clean up resources
    }

    @Override
    public void printProviders() {
        SNBIRegistrar.INSTANCE.printProviders();
    }

    @Override
    public void printWhiteList() {
        SNBIRegistrar.INSTANCE.printWhiteList();
    }
}
