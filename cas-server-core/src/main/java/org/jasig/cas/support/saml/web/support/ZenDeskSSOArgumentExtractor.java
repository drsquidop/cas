package org.jasig.cas.support.saml.web.support;

import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.support.saml.authentication.principal.ZenDeskSSOService;
import org.jasig.cas.support.saml.util.CredentialAccess;
import org.jasig.cas.web.support.AbstractSingleSignOutEnabledArgumentExtractor;
import org.opensaml.xml.security.credential.Credential;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;

/**
 * Created with IntelliJ IDEA.
 * User: doug
 * Date: 9/8/13
 * Time: 11:38 AM
 * To change this template use File | Settings | File Templates.
 */
public class ZenDeskSSOArgumentExtractor extends AbstractSingleSignOutEnabledArgumentExtractor {
    @NotNull
    private CredentialAccess credentialAccess;

    private String alternateUsername;

    public WebApplicationService extractServiceInternal(final HttpServletRequest request) {
        return ZenDeskSSOService.createServiceFrom(request, credentialAccess, alternateUsername);
    }

    /**
     * Sets an alternate username to send to the service provider (i.e. fully qualified email address).  Relies on an appropriate
     * attribute available for the user.
     * <p>
     * Note that this is optional and the default is to use the normal identifier.
     *
     * @param alternateUsername the alternate username.  This is OPTIONAL.
     */
    public void setAlternateUsername(final String alternateUsername) {
        this.alternateUsername = alternateUsername;
    }

    /**
     * Sets the Saml Credential
     * <p>
     *
//     * @param credential the SAML credential
     */
    public void setCredential(final CredentialAccess credentialAccess) {
        this.credentialAccess = credentialAccess;
    }
}
