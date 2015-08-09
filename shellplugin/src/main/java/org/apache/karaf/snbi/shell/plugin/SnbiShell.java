/*
 * Copyright (c) 2014, 2015 Cisco Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.apache.karaf.snbi.shell.plugin;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Argument;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.opendaylight.snbi.southplugin.Snbi;

@SuppressWarnings("deprecation")
@Command(scope = "snbi", name = "start", description="Start Snbi for a given Domain")
public class SnbiShell extends OsgiCommandSupport {
    @SuppressWarnings("deprecation")
    @Argument(index = 0, name = "DomainName", description = "Name of the domain", required = true, multiValued = false)
    String domainName = null;

    @Override
    protected Object doExecute() throws Exception {
        System.out.println("Starting SNBI for domain:"+domainName);
        Snbi snbiInstance = new Snbi(domainName);
        // TODO get NEighbor and bootstrap information as well.
        return null;
    }

}
