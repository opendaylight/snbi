package org.opendaylight.snbi.config.yang.config.snbi.provider.impl;

import org.opendaylight.controller.sal.binding.api.data.DataProviderService;
import org.opendaylight.snbi.southplugin.dependencies.mgrs.BundleContextDependencyManager;
import org.opendaylight.snbi.southplugin.dependencies.mgrs.MountingServiceDependencyManager;
import org.opendaylight.snbi.southplugin.util.AutoCloseableManager;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiProviderModule extends org.opendaylight.snbi.config.yang.config.snbi.provider.impl.AbstractSnbiProviderModule {

    private final AutoCloseableManager closeMgr = new AutoCloseableManager();
    private final Logger logger = LoggerFactory.getLogger(SnbiProviderModule.class);
    private BundleContext bundleContext;

    public SnbiProviderModule(org.opendaylight.controller.config.api.ModuleIdentifier identifier, org.opendaylight.controller.config.api.DependencyResolver dependencyResolver) {
        super(identifier, dependencyResolver);
    }

    public SnbiProviderModule(org.opendaylight.controller.config.api.ModuleIdentifier identifier, org.opendaylight.controller.config.api.DependencyResolver dependencyResolver, org.opendaylight.snbi.config.yang.config.snbi.provider.impl.SnbiProviderModule oldModule, java.lang.AutoCloseable oldInstance) {
        super(identifier, dependencyResolver, oldModule, oldInstance);
    }

    public void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }

    @Override
    public void customValidation() {
        // add custom validation form module attributes here.
    }

    @Override
    public java.lang.AutoCloseable createInstance() {

        DataProviderService dataBrokerService = getDataBrokerDependency();

        //Holds references to service retrieve via the data broker.
        //DEMOSTRATES: How to get services via the config sub system (data broker).
        final MountingServiceDependencyManager dependencyManager = new MountingServiceDependencyManager();
        getDomRegistryDependency().registerProvider(dependencyManager, bundleContext);
        closeMgr.add( dependencyManager );

        //Holds references to service retrieve via the bundle context (pure OSGi)
        //DEMOSTRATES: How to get services from OSGi's bundle context when you can't get to them
        //via the BrokerService (config sub system).
        final BundleContextDependencyManager bundleContextMgr = new BundleContextDependencyManager();
        bundleContextMgr.setBundleContext( bundleContext );
        bundleContextMgr.init();
        closeMgr.add( bundleContextMgr );

        return null;
    }

}
