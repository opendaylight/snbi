/*
 * Copyright (c) 2013 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.certmgmt;

import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The internal implementation of the Certificate Manager.
 */
public class CertManager implements ICertManager {
    private static final Logger logger = LoggerFactory.getLogger(CertManager.class);
    /**
     * Function called by the dependency manager when all the required
     * dependencies are satisfied
     *
     */
    void init(){
        System.out.println(" CertManager Init ..");
    }

    /**
     * Function called by the dependency manager when at least one dependency
     * become unsatisfied or when the component is shutting down because for
     * example bundle is being stopped.
     *
     */
    void destroy() {
        System.out.println(" CertManager destroy ..");
    }

    /**
     * Function called by dependency manager after "init ()" is called and after
     * the services provided by the class are registered in the service registry
     *
     */
    void start() {
        System.out.println(" CertManager::Start ..");
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
        bundleContext.registerService(CertManager.class.getName(), this, null);
        SNBIRegistrar.INSTANCE.init();
    }

    /**
     * Function called by the dependency manager before the services exported by
     * the component are unregistered, this will be followed by a "destroy ()"
     * calls
     *
     */
    void stop() {
        System.out.println(" CertManager::Stop ..");
    }

    @Override
    public void printProviders() {
        System.out.println(" CertManager::printProviders");
        SNBIRegistrar.INSTANCE.printProviders();
    }

    @Override
    public void printWhiteList() {
        System.out.println(" CertManager::printWhiteList");
        SNBIRegistrar.INSTANCE.printWhiteList();
    }

}
