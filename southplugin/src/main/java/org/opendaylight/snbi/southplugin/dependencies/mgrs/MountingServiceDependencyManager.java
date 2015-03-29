package org.opendaylight.snbi.southplugin.dependencies.mgrs;

import java.util.Collection;
import java.util.Collections;
import org.opendaylight.controller.md.sal.dom.api.DOMMountPointService;
import org.opendaylight.controller.sal.core.api.Broker.ProviderSession;
import org.opendaylight.controller.sal.core.api.Provider;
import org.opendaylight.controller.sal.core.api.model.SchemaService;
import org.opendaylight.snbi.southplugin.util.AutoCloseableManager;
import org.opendaylight.yangtools.concepts.ListenerRegistration;
import org.opendaylight.yangtools.yang.model.api.SchemaContext;
import org.opendaylight.yangtools.yang.model.api.SchemaContextListener;

/**
 * This class is responsible for extracting and holding a reference to all of the services that
 * are advertised via the config system (i.e. implements the {BrokerService} interface.
 *
 * Here we are specifically getting and using the {@link DOMMountPointService} for mounting our
 * requests onto a particular node in the data model tree.
 *
 * <Br><br>DEMOSTRATES: How to get services via the config sub system (data broker).
 * @author Devin Avery
 * @author Greg Hall
 */
public class MountingServiceDependencyManager implements SchemaContextListener,
                                                     Provider,
                                                     AutoCloseable {
    //TODO: we made these volatile as we don't truely understand on which thread "onSessionInitiated"
    //will be called
    private volatile DOMMountPointService mountService;
    private volatile SchemaContext globalSchemaContext;

    private final AutoCloseableManager closeables = new AutoCloseableManager();

    @Override
    public Collection<ProviderFunctionality> getProviderFunctionality() {
        //TODO: Understand what we are suppose to actually return here...
        return Collections.emptySet();
    }

    @Override
    public void onSessionInitiated(ProviderSession session) {
        //The DOMMountPointService is required to mount an RPC implementation, or data reader for
        //a particular node.
        mountService = session.getService(DOMMountPointService.class);

        //The schema service allows us to reference and gain access to all compiled yang models
        //in ODL (i.e. the "Global Schema"). Since we ship our yang files as part of ODL we can
        //reuse the definition here to make our life easier!
        SchemaService schemaService = session.getService( SchemaService.class );

        //TODO: Given that the returned SchemaServiceListener is deprecated, there might be a
        //better way to do this. :)

        ListenerRegistration<SchemaContextListener> schemaListenerRegistration =
        		schemaService.registerSchemaContextListener(this);

        //make sure you unregister your listeners on close.
        closeables.add( schemaListenerRegistration );
    }

    @Override
    public void close() throws Exception {
        closeables.close(); //make sure you close out
    }

    public SchemaContext getGlobalSchemaContext() {
        return globalSchemaContext;
    }

    public DOMMountPointService getMountService() {
        return mountService;
    }

    @Override
    public void onGlobalContextUpdated(SchemaContext context) {
        this.globalSchemaContext = context;
    }

//  If you want to compile yang files on the fly then this is sample code of how to do that, given
//  that you have access to all of the required yang files. In our case we use the bundle context
//  to get the internal global Schema Context that already has our compiled yang files.
//
//  private SchemaContext getSchemaContext()
//  {
//      YangParserImpl parser = new YangParserImpl();
//      try {
//          InputStream icmpdataStream =  new FileInputStream( "cache/schema/icmpdata@2014-05-15.yang");
//          InputStream ietfNettypes =  new FileInputStream( "cache/schema/ietf-inet-types@2010-09-24.yang");
//          Preconditions.checkNotNull( icmpdataStream );
//          Set<Module> models = parser.parseYangModelsFromStreams( Arrays.asList( icmpdataStream, ietfNettypes ));
//          return parser.resolveSchemaContext(models);
//      } catch (Exception e) {
//          e.printStackTrace();
//          return null;
//      }
//  }
}
