package org.jasig.cas.support.saml.util;

import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created with IntelliJ IDEA.
 * User: doug
 * Date: 9/9/13
 * Time: 8:34 AM
 * To change this template use File | Settings | File Templates.
 */
public class CredentialAccess implements Serializable {
    private final static Logger logger = LoggerFactory.getLogger(CredentialAccess.class);

    public String fileName;
    public String password;
    public String alias;

    //private Credential c = null;

    CredentialAccess(String fileName, String password, String alias) {
        this.fileName = fileName;
        this.password = password;
        this.alias = alias;
    }

    public Credential getCredential() {
//        if (c != null) {
//            return c;
//        } else {
            InputStream is;
            try {
                ClassLoader cl = Thread.currentThread().getContextClassLoader();
                is = cl.getResourceAsStream(fileName);
                KeyStore ks = null;
                char[] pw = password.toCharArray();

                // Get Default Instance of KeyStore
                try
                {
                    ks = KeyStore.getInstance(KeyStore.getDefaultType());
                }
                catch (KeyStoreException e)
                {
                    logger.error("Error while initializing keystore", e);
                }

                // Load KeyStore
                try
                {
                    ks.load(is, pw);
                }
                catch (NoSuchAlgorithmException e)
                {
                    logger.error("Failed to Load the KeyStore:: ", e);
                }
                catch (CertificateException e)
                {
                    logger.error("Failed to Load the KeyStore:: ", e);
                }
                catch (IOException e)
                {
                    logger.error("Failed to Load the KeyStore:: ", e);
                }

                // Get Private Key Entry From Certificate
                KeyStore.PrivateKeyEntry pkEntry = null;
                try
                {
                    pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(
                            pw));
                }
                catch (NoSuchAlgorithmException e)
                {
                    logger.error("Failed to Get Private Entry From the keystore:: " + fileName, e);
                }
                catch (UnrecoverableEntryException e)
                {
                    logger.error("Failed to Get Private Entry From the keystore:: " + fileName, e);
                }
                catch (KeyStoreException e)
                {
                    logger.error("Failed to Get Private Entry From the keystore:: " + fileName, e);
                }
                PrivateKey pk = pkEntry.getPrivateKey();

                X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
                BasicX509Credential credential = new BasicX509Credential();
                credential.setEntityCertificate(certificate);
                credential.setPrivateKey(pk);

//                c = credential;
                return credential;

//            } catch (IOException e) {
//                logger.error("IOException creating input stream for resource", e);
            } finally {
////                is.close();
//                return c;
            }
//        }
    }
}
