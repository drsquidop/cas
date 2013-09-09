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
        return new CredentialAccess(resource, password, alias);
    }

    public Class getObjectType() {
        return CredentialAccess.class;
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
