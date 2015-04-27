/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution, 
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#ifndef __AN_OLIBC_H__
#define __AN_OLIBC_H__

static inline an_cerrno
an_map_olibc_retval (olibc_api_retval_t olibc_retval)
{
    switch (olibc_retval) {
        case OLIBC_RETVAL_SUCCESS:
        case OLIBC_RETVAL_EMPTY_DATA_SET:
            return (AN_CERR_SUCCESS);
        case OLIBC_RETVAL_MIN:
        case OLIBC_RETVAL_INVALID_INPUT:
        case OLIBC_RETVAL_FAILED:
        case OLIBC_RETVAL_MAX:
        default:
            return (1);
    }
}
