/*
 * Copyright (c) 2014 Ericsson India Global Services Pvt Ltd. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.snbi.southplugin;

import java.security.cert.X509Certificate;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SNBITest {
	protected static final Logger logger = LoggerFactory
            .getLogger(SNBITest.class);;
	
	
	@Before
	public void testInit(){
    }
	
	@Test
	public void testSNBICertInitialization() {
		logger.info( " SNBI Registrar Initialization - " );
		 CertRegistrar.INSTANCE.init();
	}
	
	@Test
    public void testCSR(){
		logger.info( "Testing CSR- " + this );
        org.bouncycastle.pkcs.PKCS10CertificationRequest certRequest =
             SNBICAInterfaces.INSTANCE.generateCSRRequest(new String[]{"My Name","Ericsson","101"});
        Assert.assertNotNull(certRequest);
        logger.info("Created the CSR "+certRequest.toString());
    }
 
    @Test
    public void testCreateCertificate(){
    	testSNBICertInitialization();
        System.out.println( "Testing creation of X509 certificate Two - " + this );
        org.bouncycastle.pkcs.PKCS10CertificationRequest certRequest =
                SNBICAInterfaces.INSTANCE.generateCSRRequest(new String[]{"My Name","Ericsson","101"});
        Assert.assertNotNull(certRequest);
        X509Certificate certificate = SNBICAInterfaces.INSTANCE.generateX509Certificate(certRequest,null);
        Assert.assertNotNull(certificate);
    }

    @After
    public void testCleanUp(){

    }
    
    @AfterClass
    public static void staticCleanUp(){
    }
    
    public void test() {
    }
    
}
