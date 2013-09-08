package org.jasig.cas.support.saml.util;

import junit.framework.TestCase;
import org.jasig.cas.support.saml.authentication.principal.ZenDeskSSOService;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.InputStream;

public class SamlCertUtilTests extends TestCase {

    private final static Logger logger = LoggerFactory.getLogger(SamlCertUtils.class);

    public Response getResponseFromFile(String filename) throws XMLParserException, UnmarshallingException, ConfigurationException {
        // Initialize the library
        DefaultBootstrap.bootstrap();

        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);

        // Parse metadata file
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream in = classLoader.getResourceAsStream(filename);

        Document inCommonMDDoc = ppMgr.parse(in);
        Element metadataRoot = inCommonMDDoc.getDocumentElement();

        // Get appropriate unmarshaller
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);

        // Unmarshall using the document root element, an EntitiesDescriptor in this case
        Response response = (Response) unmarshaller.unmarshall(metadataRoot);
        return response;
    }

    public void testSigningAssertion() throws Exception
    {
        final CredentialFactoryBean credentialFactoryBean = new CredentialFactoryBean();

        final ClassPathResource credentialResource = new ClassPathResource("keystore.jks");
        credentialFactoryBean.setLocation(credentialResource);
        credentialFactoryBean.setAlias("selfsigned");
        credentialFactoryBean.setPassword("password");

        assertTrue(credentialFactoryBean.getObjectType().equals(Credential.class));
        credentialFactoryBean.afterPropertiesSet();

        Credential signingCredential = (Credential) credentialFactoryBean.getObject();


        Response resp = null;
        try {
            resp = getResponseFromFile("sampleResponseZenDesk.xml");
        } catch (XMLParserException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (UnmarshallingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (ConfigurationException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }

        SamlCertUtils.signResponse(signingCredential, resp);

        ResponseMarshaller marshaller = new ResponseMarshaller();
        Element plain = null;
        try {
            plain = marshaller.marshall(resp);
        } catch (MarshallingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        // response.setSignature(sign);
        String samlResponse = XMLHelper.nodeToString(plain);
        SamlTestUtils.saveFile("response2.xml", samlResponse);

        //validate
        //create SignatureValidator
        SignatureValidator signatureValidator = new SignatureValidator(signingCredential);

        //get the signature to validate from the response object
        Assertion assertion = (Assertion) resp.getAssertions().get(0);
        Signature sig2 = assertion.getSignature();

        //try to validate
        try
        {
            signatureValidator.validate(sig2);
        }
        catch (ValidationException ve)
        {
            System.out.println("Signature is NOT valid.");
            System.out.println(ve.getMessage());
            fail();
        }
    }

}
