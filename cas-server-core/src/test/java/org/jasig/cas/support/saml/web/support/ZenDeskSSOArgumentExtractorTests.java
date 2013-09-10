/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.support.saml.web.support;

import junit.framework.TestCase;
import org.jasig.cas.support.saml.util.CredentialAccess;
import org.jasig.cas.support.saml.util.CredentialFactoryBean;
import org.opensaml.xml.security.credential.Credential;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;

public class ZenDeskSSOArgumentExtractorTests extends TestCase {
    
    private ZenDeskSSOArgumentExtractor extractor;

    protected void setUp() throws Exception {
        final CredentialFactoryBean credentialFactoryBean = new CredentialFactoryBean();

        //final ClassPathResource credentialResource = new ClassPathResource("keystore.jks");
        credentialFactoryBean.setLocation("keystore.jks");
        credentialFactoryBean.setAlias("selfsigned");
        credentialFactoryBean.setPassword("password");

        assertTrue(credentialFactoryBean.getObjectType().equals(CredentialAccess.class));
        credentialFactoryBean.afterPropertiesSet();

        this.extractor = new ZenDeskSSOArgumentExtractor();
        this.extractor.setCredential((CredentialAccess) credentialFactoryBean.getObject());

        super.setUp();
    }
    
    public void testNoService() {
        assertNull(this.extractor.extractService(new MockHttpServletRequest()));
    }
}
