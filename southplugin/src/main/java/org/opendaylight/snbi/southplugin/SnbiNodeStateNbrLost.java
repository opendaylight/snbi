/*
 * Copyright (c) 2014, 2015 Cisco Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.southplugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiNodeStateNbrLost extends SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {
    private static final Logger log = LoggerFactory.getLogger(SnbiNodeStateNewNbr.class);

    public SnbiNodeStateNbrLost (SnbiNode node) {
        super(node);
    }

    public SnbiNodeState getState () {
        return SnbiNodeState.SNBI_NODE_STATE_NBR_LOST;
    }

    @Override
    public SnbiNodeState nodeStateSetEvent(eventContext evt) {
        log.debug("[node:"+node.getUDI()+"] Set state : "+this.getState());
        return node.getCurrState();
    }

}
