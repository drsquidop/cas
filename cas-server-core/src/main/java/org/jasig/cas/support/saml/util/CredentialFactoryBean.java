package org.jasig.cas.support.saml.util;

import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.core.io.Resource;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
* Credential factory bean loads a java keystore based X509 certificate and RSA key pairs as a Saml Credential
 */
public class CredentialFactoryBean extends AbstractFactoryBean {
    private final static Logger logger = LoggerFactory.getLogger(CredentialFactoryBean.class);

    @NotNull
    private Resource resource;
    @NotNull
    private String alias;
    @NotNull
    private String password;

    protected final Object createInstance() throws Exception {
        final InputStream is = resource.getInputStream();
        try {
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
                logger.error("Failed to Get Private Entry From the keystore:: " + resource.toString(), e);
            }
            catch (UnrecoverableEntryException e)
            {
                logger.error("Failed to Get Private Entry From the keystore:: " + resource.toString(), e);
            }
            catch (KeyStoreException e)
            {
                logger.error("Failed to Get Private Entry From the keystore:: " + resource.toString(), e);
            }
            PrivateKey pk = pkEntry.getPrivateKey();

            X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
            BasicX509Credential credential = new BasicX509Credential();
            credential.setEntityCertificate(certificate);
            credential.setPrivateKey(pk);

            return credential;
        } finally {
            is.close();
        }
    }

    public Class getObjectType() {
        return Credential.class;
    }

    public void setLocation(final Resource resource) {
        this.resource = resource;
    }

    public void setAlias(final String alias) {
        this.alias = alias;
    }

    public void setPassword(final String password) {
        this.password = password;
    }
}
