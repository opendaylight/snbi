/*
 * Copyright (c) 2014, 2015 Ericsson Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.southplugin;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.eclipse.osgi.framework.console.CommandInterpreter;
import org.eclipse.osgi.framework.console.CommandProvider;
import org.opendaylight.controller.md.sal.binding.api.DataChangeListener;
import org.opendaylight.controller.md.sal.common.api.data.AsyncDataChangeEvent;
import org.opendaylight.yang.gen.v1.http.netconfcentral.org.ns.snbi.rev240702.SnbiDomain;
import org.opendaylight.yangtools.yang.binding.DataObject;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * Singleton instance for certificate manager
 */
public class CertManager implements ICertManager, CommandProvider ,DataChangeListener {

    private static final Logger logger = LoggerFactory.getLogger(CertManager.class);
    private static CertManager certManager = null;
    private CertManager() {

    }
    public static CertManager getInstance() {
    	if (certManager == null) {
    		synchronized(CertManager.class) {
    			if (certManager == null)
    				certManager = new CertManager();
    		}
    	}
    	return certManager;
    }

    // Start method called by Activator
    // Initialize the SNBI registrar
    void start() {
        logger.info(" CertManager::Starting");
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
        bundleContext.registerService(CommandProvider.class.getName(), this,
                null);
        CertRegistrar.INSTANCE.init();
    }

    void stop() {
        // to do later for clean up resources
    }

    @Override
    public String getHelp() {
        StringBuffer help = new StringBuffer();
        help.append("\t\n---SNBI Certificate Manager---\n");
        help.append("\t printProviders \n");
        help.append("\t printWhiteListFromStore\n");
        help.append("\t populateWhileListFromStore\n");
        help.append("\t printWhiteListFromFile\n");
        help.append("\t printCertificateLocation\n");
        help.append("\t API , used by other bundles \n");
        help.append("\t-----------------------------------------------------------------------------------\n");
        help.append("\t PKCS10CertificationRequest generateCSRRequest(String... arguments)\n");
        help.append("\t X509Certificate generateX509Certificate(PKCS10CertificationRequest request, ContentSigner signer)\n");
        help.append("\t boolean compareCertificates(Certificate cert1, Certificate cert2)\n");
        help.append("\t HashMap<String,String> getCertificateInfo(X509Certificate cert)\n");
        help.append("\t X509Certificate getRootCACertificate()\n");
        help.append("\t String saveCertificate(X509Certificate cert)\n");
        help.append("\t X509Certificate getSavedCertificate(String alias)\n");
        help.append("\t String verifyCertificate(X509Certificate cert, Date date, PublicKey pub_key)\n");
        help.append("\t byte[] generateSignature(byte[] data, Certificate cert,String algorithm) \n");
        help.append("\t boolean verifySignature(byte[] data,byte[] hash,Certificate cert,String algorithm) \n");
        help.append("\t-----------------------------------------------------------------------------------\n");
        return help.toString();
    }

    @Override
    public void printProviders() {
        CertRegistrar.INSTANCE.printProviders();
    }

    @Override
    public void printWhiteListFromFile() {
        CertRegistrar.INSTANCE.printWhiteListFromFile();;
    }

    @Override
    public void printWhiteListFromStore() {
        CertRegistrar.INSTANCE.printWhiteListFromStore();;
    }

    @Override
    public void populateWhileListFromStore() {
        CertRegistrar.INSTANCE.populateWhileListFromStore();
    }

    @Override
    public PKCS10CertificationRequest generateCSRRequest(String... arguments) {
        return SNBICAInterfaces.INSTANCE.generateCSRRequest(arguments);
    }

    @Override
    public X509Certificate generateX509Certificate(PKCS10CertificationRequest request, ContentSigner signer) {
        return SNBICAInterfaces.INSTANCE.generateX509Certificate(request, signer);
    }

    @Override
    public boolean compareCertificates(Certificate cert1, Certificate cert2) {
        return SNBICAInterfaces.INSTANCE.compareCertificates(cert1, cert2);
    }

    @Override
    public HashMap<String,String> getCertificateInfo(X509Certificate cert){
        return SNBICAInterfaces.INSTANCE.getCertificateInfo(cert);
    }

    @Override
    public String saveCertificate(X509Certificate cert) {
        return SNBICAInterfaces.INSTANCE.saveCertificate(cert);
    }

    @Override
    public X509Certificate getSavedCertificate(String alias) {
        return SNBICAInterfaces.INSTANCE.getSavedCertificate(alias);
    }

    @Override
    public X509Certificate getRootCACertificate() {
        return SNBICAInterfaces.INSTANCE.getRootCACertificate();
    }

    @Override
    public String verifyCertificate(X509Certificate cert, Date date, PublicKey pub_key) {
        return SNBICAInterfaces.INSTANCE.verifyCertificate(cert, date, pub_key);
    }

    @Override
    public byte[] generateSignature(byte[] data, Certificate cert,String algorithm) {
        return SNBICAInterfaces.INSTANCE.generateSignature(data, cert, algorithm);
    }

    @Override
    public  boolean verifySignature(byte[] data,byte[] hash,Certificate cert,String algorithm) {
        return SNBICAInterfaces.INSTANCE.verifySignature(data, hash, cert, algorithm);
    }

    /*  For OSGI Console */
    public void _snbi(CommandInterpreter ci) {
        String argument = ci.nextArgument();
        if(argument != null && argument.compareToIgnoreCase("help") == 0)
        {
            StringBuffer help = new StringBuffer();
            help.append("\t\n---SNBI Certificate Manager---\n");
            help.append("\t printProviders \n");
            help.append("\t printWhiteListFromStore\n");
            help.append("\t populateWhileListFromStore\n");
            help.append("\t printWhiteListFromFile\n");
            help.append("\t printCertificateLocation\n");
            help.append("\t API , used by other bundles \n");
            help.append("\t-----------------------------------------------------------------------------------\n");
            help.append("\t PKCS10CertificationRequest generateCSRRequest(String... arguments)\n");
            help.append("\t X509Certificate generateX509Certificate(PKCS10CertificationRequest request, ContentSigner signer)\n");
            help.append("\t boolean compareCertificates(Certificate cert1, Certificate cert2)\n");
            help.append("\t HashMap<String,String> getCertificateInfo(X509Certificate cert)\n");
            help.append("\t X509Certificate getRootCACertificate()\n");
            help.append("\t String saveCertificate(X509Certificate cert)\n");
            help.append("\t X509Certificate getSavedCertificate(String alias)\n");
            help.append("\t String verifyCertificate(X509Certificate cert, Date date, PublicKey pub_key)\n");
            help.append("\t byte[] generateSignature(byte[] data, Certificate cert,String algorithm) \n");
            help.append("\t boolean verifySignature(byte[] data,byte[] hash,Certificate cert,String algorithm) \n");
            help.append("\t-----------------------------------------------------------------------------------\n");
            logger.info(help.toString());
        }
    }

    public void _printProviders(CommandInterpreter ci) {
        CertRegistrar.INSTANCE.printProviders();
    }

    public void _printWhiteListFromStore(CommandInterpreter ci) {
        CertRegistrar.INSTANCE.printWhiteListFromStore();
    }

    public void _populateWhileListFromStore(CommandInterpreter ci) {
        CertRegistrar.INSTANCE.populateWhileListFromStore();
    }

    public void _printWhiteListFromFile(CommandInterpreter ci) {
        CertRegistrar.INSTANCE.printWhiteListFromFile();
    }

    public void _printCertificateLocation(CommandInterpreter ci) {
        logger.info("\n"+CertManagerConstants.KEY_CERT_PATH+"\n");
    }

   @Override
   public void onDataChanged(
		AsyncDataChangeEvent<InstanceIdentifier<?>, DataObject> change) {
	logger.info("SNBI Data Change Event received . ");
	 DataObject dataObject = change.getUpdatedSubtree();
      if( dataObject instanceof SnbiDomain ) {
    	  CertRegistrar.INSTANCE.populateWhileListFromStore();
    	  CertRegistrar.INSTANCE.printWhiteListFromStore();
    	  /*
    	  SnbiDomain snbiDomain = (SnbiDomain)dataObject;
    	  logger.info("SNBI Data Chnage Event :: Domain Name = "+snbiDomain.getDomainName());
    	  List<DeviceList> deviceList = snbiDomain.getDeviceList();
    	  if (deviceList != null) {
    		  for (DeviceList device : deviceList ) {
    			  logger.info("List Name = "+device.getListName());
    			  logger.info("List Type = "+device.getListType().name());
    			  logger.info("Active = "+device.isActive());
    			  List<Devices> devices = device.getDevices();
    			  if (devices != null) {
    				  for (Devices single : devices) {
    					  logger.info("Device Id = "+single.getDeviceId());
    					  logger.info("Device Key = "+single.getKey());
    				  }
    			  }
    		  }
    	  }
    	  */
      }
   }
}

