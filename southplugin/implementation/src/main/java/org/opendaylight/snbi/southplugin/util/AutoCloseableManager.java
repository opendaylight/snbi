package org.opendaylight.snbi.southplugin.util;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maintains a list of AutoCloseable objects, and when its "close" method is called, it iterates
 * through the list, closing each auto closeable object, and subsequently removing that object
 * from the list.
 * <br>
 * Note: This class is thread safe, and does NOT need to be synchronized during concurrent access.
 *
 */
public class AutoCloseableManager implements AutoCloseable {

    private final Logger log = LoggerFactory.getLogger( AutoCloseableManager.class );

    private final boolean isClosed = false;
    private final Set<AutoCloseable> autoCloseables = new HashSet<>();

    public void add( AutoCloseable ac )
    {
        boolean close = false;
        synchronized( autoCloseables )
        {
            if( isClosed ){
                log.info( "Closing " + ac + " as this manager has already been closed.");
                close = true;
            }
            else
            {
                autoCloseables.add( ac );
            }
        }
        if( close )
        {
            safeClose(ac);
        }
    }


    @Override
    public void close() throws Exception {

        Set<AutoCloseable> toClose;
        synchronized( autoCloseables )
        {
            toClose = new HashSet<>( autoCloseables );
            autoCloseables.clear();
        }

        for( AutoCloseable close : toClose )
        {
            safeClose(close);
        }
    }


    private void safeClose(AutoCloseable next) {
        try{
            safeClose(next);
        } catch( Exception e )
        {
            log.error( "Uncaught exception while closing object " + next, e );
        }
    }

}
