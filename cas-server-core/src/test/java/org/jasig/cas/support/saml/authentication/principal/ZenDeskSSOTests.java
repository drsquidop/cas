package org.jasig.cas.support.saml.authentication.principal;

import junit.framework.TestCase;
import org.jasig.cas.TestUtils;
import org.jasig.cas.support.saml.util.CredentialAccess;
import org.jasig.cas.support.saml.util.CredentialFactoryBean;
import org.jasig.cas.support.saml.util.SamlTestUtils;
import org.opensaml.xml.security.credential.Credential;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created with IntelliJ IDEA.
 * User: doug
 * Date: 9/8/13
 * Time: 11:49 AM
 * To change this template use File | Settings | File Templates.
 */
public class ZenDeskSSOTests extends TestCase {
    private ZenDeskSSOService ssoService;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    public static ZenDeskSSOService getGoogleAccountsService() throws Exception {
        final CredentialFactoryBean credentialFactoryBean = new CredentialFactoryBean();

        final ClassPathResource credentialResource = new ClassPathResource("keystore.jks");
        credentialFactoryBean.setLocation(credentialResource);
        credentialFactoryBean.setAlias("selfsigned");
        credentialFactoryBean.setPassword("password");

        assertTrue(credentialFactoryBean.getObjectType().equals(CredentialAccess.class));
        credentialFactoryBean.afterPropertiesSet();

        CredentialAccess credential = (CredentialAccess) credentialFactoryBean.getObject();

        final MockHttpServletRequest request = new MockHttpServletRequest();

        final String SAMLRequest = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"saml-5545454455\" Version=\"2.0\" IssueInstant=\"Value\" ProtocolBinding=\"urn:oasis:names.tc:SAML:2.0:bindings:HTTP-Redirect\" ProviderName=\"https://localhost:8443/myRutgers\" AssertionConsumerServiceURL=\"https://localhost:8443/myRutgers\"/>";
        request.setParameter("SAMLRequest", SamlTestUtils.encodeMessage(SAMLRequest));

        return ZenDeskSSOService.createServiceFrom(request, credential.getCredential(), null);
    }

    protected void setUp() throws Exception {
        this.ssoService = getGoogleAccountsService();
        this.ssoService.setPrincipal(TestUtils.getPrincipal());
    }

    public void testOpenSamlXmlResponse() {
        String ticketId = "ticketId";
        String signedResponse = this.ssoService.getSignedResponse(ticketId);

        SamlTestUtils.saveFile("response.xml", signedResponse);
    }

}

