/*
 * Copyright (c) 2014, 2015 Cisco Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.southplugin;
/**
 * Interface for the messaging service.
 */
interface ISnbiMsgInfraPktsListener {
    void incomingNodeCertReqPktsListener(SnbiPkt pkt);

    void incomingNodeCertRespPktsListener(SnbiPkt pkt);

    void incomingNodeConnectPktsListener(SnbiPkt pkt);
  
    void incomingNodeBSReqPktsListener(SnbiPkt pkt);
}

