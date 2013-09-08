package org.jasig.cas.support.saml.util;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * SamCertUtils add OpenSaml, ZenDesk compliant operations to CAS
 */
public class SamlCertUtils
{
    private final static Logger logger = LoggerFactory.getLogger(SamlCertUtils.class);
    final static String password = "password";
    final static String certificateAliasName = "selfsigned";
    final static String fileName = "keystore.jks";

    public static Response getResponseFromString(String resp) throws XMLParserException, UnmarshallingException, ConfigurationException {
        // Initialize the library
        DefaultBootstrap.bootstrap();

        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);

        // Parse metadata file
        StringReader sr = new StringReader(resp);

        Document inCommonMDDoc = ppMgr.parse(sr);
        Element metadataRoot = inCommonMDDoc.getDocumentElement();

        // Get apropriate unmarshaller
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);

        // Unmarshall using the document root element, an EntitiesDescriptor in this case
        Response response = (Response) unmarshaller.unmarshall(metadataRoot);
        return response;
    }

    public static Response signResponse(Credential c, Response resp) {
        Signature signature = null;
        try
        {
            DefaultBootstrap.bootstrap();
        }
        catch (ConfigurationException e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        signature = (Signature) Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(c);

        // This is also the default if a null SecurityConfiguration is specified
        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
        // If null this would result in the default KeyInfoGenerator being used
        String keyInfoGeneratorProfile = "XMLSignature";

        try
        {
            SecurityHelper.prepareSignatureParams(signature, c, secConfig, null);
        }
        catch (SecurityException e)
        {
            e.printStackTrace();
        }
        catch (org.opensaml.xml.security.SecurityException e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        //resp.setSignature(signature);
        Assertion assertion = (Assertion) resp.getAssertions().get(0);
        assertion.setSignature(signature);
//        Response response = (Response) Configuration.getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME)
//                .buildObject(Response.DEFAULT_ELEMENT_NAME);

        try
        {
            Configuration.getMarshallerFactory().getMarshaller(resp).marshall(resp);
        }
        catch (MarshallingException e)
        {
            e.printStackTrace();
        }

        try
        {
            Signer.signObject(signature);
        }
        catch (SignatureException e)
        {
            e.printStackTrace();
        }
        return resp;
    }
}