// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.leverandor;

import java.net.URI;
import java.util.GregorianCalendar;
import java.util.Map;
import javax.xml.datatype.DatatypeFactory;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;

/** Builds the brokered context the mappers read, without a running server. */
final class TestAssertions {

    static final String DN =
            "C=DK,O=11715311,CN=Hans Hansen,Serial=74c08b2b-212b-4f6d-9ce6-0fba1651087d";

    private TestAssertions() {}

    /**
     * @param nameIdValue the Subject NameID, or {@code null} for an assertion
     *     without one
     * @param attributes attribute name to single value
     */
    static BrokeredIdentityContext context(String nameIdValue, Map<String, String> attributes) {
        return context(nameIdValue, SamlAssertions.X509_SUBJECT_NAME, attributes);
    }

    /** As {@link #context(String, Map)}, with the NameID in the given format. */
    static BrokeredIdentityContext context(
            String nameIdValue, String nameIdFormat, Map<String, String> attributes) {
        BrokeredIdentityContext context =
                new BrokeredIdentityContext("id", new IdentityProviderModel());

        AssertionType assertion =
                new AssertionType(
                        "assertion-id",
                        DatatypeFactory.newDefaultInstance()
                                .newXMLGregorianCalendar(new GregorianCalendar()));

        if (nameIdValue != null) {
            NameIDType nameId = new NameIDType();
            nameId.setValue(nameIdValue);
            nameId.setFormat(URI.create(nameIdFormat));
            SubjectType.STSubType subType = new SubjectType.STSubType();
            subType.addBaseID(nameId);
            SubjectType subject = new SubjectType();
            subject.setSubType(subType);
            assertion.setSubject(subject);
        }

        if (attributes != null && !attributes.isEmpty()) {
            AttributeStatementType statement = new AttributeStatementType();
            attributes.forEach(
                    (name, value) -> {
                        AttributeType attribute = new AttributeType(name);
                        attribute.addAttributeValue(value);
                        statement.addAttribute(new AttributeStatementType.ASTChoiceType(attribute));
                    });
            assertion.addStatement(statement);
        }

        context.getContextData().put(SAMLEndpoint.SAML_ASSERTION, assertion);
        return context;
    }

    static IdentityProviderMapperModel config(Map<String, String> config) {
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setConfig(config);
        return model;
    }
}
