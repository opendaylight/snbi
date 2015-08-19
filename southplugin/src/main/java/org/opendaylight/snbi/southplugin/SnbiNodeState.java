/*
 * Copyright (c) 2014, 2015 Cisco Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.southplugin;

public enum SnbiNodeState {
    SNBI_NODE_STATE_REGISTRAR,
    SNBI_NODE_STATE_NEW_NBR,
    SNBI_NODE_STATE_NBR_LOST,
    SNBI_NODE_STATE_NI_CERT_REQUEST,
    SNBI_NODE_BS_INVITE,
    SNBI_NODE_BS_REJECTED,
    SNBI_NODE_STATE_BOOTSTRAP,
    SNBI_NODE_STATE_BOOTSTRAP_IGNORE
}
