/*
 * Copyright (c) 2014, 2015 Cisco Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.southplugin;

import java.util.List;

import org.eclipse.osgi.framework.console.CommandInterpreter;
import org.eclipse.osgi.framework.console.CommandProvider;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The internal SNBI services.
 */
public class SnbiInternal implements CommandProvider {
    private static final Logger log = LoggerFactory
            .getLogger(SnbiInternal.class);
    Snbi snbiInstance = null;

    public String getHelp() {
        StringBuffer help = new StringBuffer();
        help.append("---SNBI Service Testing---\n");
        help.append("\tSnbiStart         - Provide a Domain Name");
        return help.toString();
    }

    public void _SnbiStart(CommandInterpreter ci) {
        String domainName = ci.nextArgument();
        if (domainName == null) {
            ci.println("Domain Name not provided.");
            return;
        }
        log.debug("Snbi START domain:"+domainName);
        snbiInstance = new Snbi(domainName);
        log.info("Starting Snbi Service for domain " + domainName);
    }

    public void _SnbiStop(CommandInterpreter ci) {
        String domainName = ci.nextArgument();
        if (domainName == null) {
            ci.println("Domain Name not provided.");
            return;
        }
    }

    public void _SnbiShowNeighbors(CommandInterpreter ci) {
        String domainName = ci.nextArgument();
        List<SnbiNode> nodes = null;
        if (domainName == null) {
            ci.println("Domain Name not provided.");
            return;
        }
        nodes = snbiInstance.getNeighbors(domainName);
        for (SnbiNode node : nodes) {
            System.out.println(" UDI: " + node.getUDI());
            System.out.println("     IF-Name:" +node.getPeerIfName());
        }
    }

    private void registerWithOSGIConsole() {
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass())
                .getBundleContext();
        bundleContext.registerService(CommandProvider.class.getName(), this,
                null);
    }

    public SnbiInternal() {
        log.debug("Snbi Constructort");
    }

    void init() {
        log.debug("INIT called!");
    }

    void destroy() {
        log.debug("DESTROY called!");
    }

    void start() throws Exception {
        log.debug("START called!");
        try {
            // Get instance will also init Messaging Infra.
            SnbiMessagingInfra.getInstance();
        } catch (Exception excpt) {
            throw excpt;
        }
        registerWithOSGIConsole();
    }

    void stop() {
        log.debug("STOP called!");
    }
}
