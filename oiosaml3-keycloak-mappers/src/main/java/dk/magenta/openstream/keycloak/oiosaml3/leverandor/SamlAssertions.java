// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.leverandor;

import java.net.URI;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;

/** Reading raw values out of the SAML assertion the broker just validated. */
final class SamlAssertions {

    /** The only NameID format the KOMBIT profile allows for a brugertoken. */
    static final String X509_SUBJECT_NAME =
            "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";

    private SamlAssertions() {}

    static AssertionType assertion(BrokeredIdentityContext context) {
        Object assertion = context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        return assertion instanceof AssertionType assertionType ? assertionType : null;
    }

    /**
     * The X509SubjectName DN in the Subject's NameID, or {@code null}.
     *
     * <p>The KOMBIT profile (section 1.4.1) puts the DN here and nowhere
     * else, with Format X509SubjectName. A NameID in any other format is not a
     * DN, and parsing it as one would key the user on whatever it happens to
     * contain, so it is treated as absent.
     */
    static String subjectDn(BrokeredIdentityContext context) {
        AssertionType assertion = assertion(context);
        if (assertion == null) {
            return null;
        }
        SubjectType subject = assertion.getSubject();
        if (subject == null || subject.getSubType() == null) {
            return null;
        }
        if (!(subject.getSubType().getBaseID() instanceof NameIDType nameId)) {
            return null;
        }
        URI format = nameId.getFormat();
        if (format == null || !X509_SUBJECT_NAME.equals(format.toString())) {
            return null;
        }
        String value = nameId.getValue();
        return value == null || value.isBlank() ? null : value.trim();
    }
}
