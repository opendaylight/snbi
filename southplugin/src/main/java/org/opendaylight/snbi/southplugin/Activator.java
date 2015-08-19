/*
 * Copyright (c) 2014, 2015 Cisco Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.southplugin;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.md.sal.binding.api.DataChangeListener;
import org.opendaylight.controller.md.sal.common.api.data.AsyncDataBroker.DataChangeScope;
import org.opendaylight.controller.md.sal.common.api.data.LogicalDatastoreType;
import org.opendaylight.controller.sal.binding.api.AbstractBindingAwareProvider;
import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.ProviderContext;
import org.opendaylight.yang.gen.v1.http.netconfcentral.org.ns.snbi.rev240702.SnbiDomain;
import org.opendaylight.yangtools.concepts.ListenerRegistration;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Activator class following the new MD-SAL path
public class Activator extends AbstractBindingAwareProvider {

	private DataBroker dataBroker;
	private static Activator INSTANCE;

	public static final InstanceIdentifier<SnbiDomain>  SNBIDOMAIN_IID = InstanceIdentifier.builder(SnbiDomain.class).build();
	private ListenerRegistration<DataChangeListener> dataChangeListenerRegistration = null;

	public static Activator getInstance() {
        return INSTANCE;
    }
	public DataBroker getDataBroker() {
        return dataBroker;
    }

    protected static final Logger logger = LoggerFactory
            .getLogger(Activator.class);

    // called during osgi start
    @Override
    public void onSessionInitiated(final ProviderContext session) {
        logger.debug("In onSessionInitiated");
        logger.debug("Initializing SNBI South Plugin Activator");
        try {
        	INSTANCE = this;
        	this.dataBroker = session.getSALService(DataBroker.class);
            SnbiInternal snbi = new SnbiInternal();
            snbi.start();
            CertManager certManager = CertManager.getInstance();
            certManager.start();
            this.dataBroker = session.getSALService(DataBroker.class);
            dataChangeListenerRegistration =
            		this.dataBroker.registerDataChangeListener(LogicalDatastoreType.CONFIGURATION,SNBIDOMAIN_IID,certManager,DataChangeScope.SUBTREE);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // called durng osgi stop
    @Override
    protected void stopImpl(final BundleContext context) {
        logger.info("SNBI South Plugin Activator clean up completed ");
    }

}
