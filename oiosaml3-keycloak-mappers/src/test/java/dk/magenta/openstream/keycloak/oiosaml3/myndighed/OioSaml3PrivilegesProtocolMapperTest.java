// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.myndighed;

import static dk.magenta.openstream.keycloak.oiosaml3.myndighed.Stubs.group;
import static dk.magenta.openstream.keycloak.oiosaml3.myndighed.Stubs.session;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dk.magenta.openstream.keycloak.oiosaml3.shared_helpers.PrivilegeListBuilder;
import dk.magenta.openstream.keycloak.oiosaml3.myndighed.Stubs.Group;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.provider.ProviderConfigProperty;

class OioSaml3PrivilegesProtocolMapperTest {

    private static final String CVR = "29189846";
    private static final String OTHER_CVR = "12345678";
    private static final String SCOPE = "urn:dk:gov:saml:cvrNumberIdentifier:";
    private static final String ROLE_ATTR = OioSaml3PrivilegesProtocolMapper.DEFAULT_GROUP_ATTRIBUTE;
    private static final String SCOPE_ATTR = OioSaml3PrivilegesProtocolMapper.DEFAULT_GROUP_SCOPE_ATTRIBUTE;

    private static final String ROLE_A = "http://kombit.dk/roles/jobrole/sagsbehandler/1";
    private static final String ROLE_B = "http://kombit.dk/roles/jobrole/leder/1";
    private static final String ROLE_C = "http://kombit.dk/roles/jobrole/delegeret/1";

    private final OioSaml3PrivilegesProtocolMapper mapper = new OioSaml3PrivilegesProtocolMapper();

    /** The config the admin console saves when only the CVR is filled in. */
    private static Map<String, String> defaults() {
        Map<String, String> config = new HashMap<>();
        for (ProviderConfigProperty property : new OioSaml3PrivilegesProtocolMapper().getConfigProperties()) {
            if (property.getDefaultValue() != null) {
                config.put(property.getName(), property.getDefaultValue().toString());
            }
        }
        config.put(OioSaml3PrivilegesProtocolMapper.CONF_SCOPE_CVR, CVR);
        return config;
    }

    private static ProtocolMapperModel model(Map<String, String> config) {
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(config);
        return model;
    }

    private AttributeStatementType run(Map<String, String> config, UserSessionModel session) {
        AttributeStatementType statement = new AttributeStatementType();
        mapper.transformAttributeStatement(statement, model(config), null, session, null);
        return statement;
    }

    private static AttributeType onlyAttribute(AttributeStatementType statement) {
        assertEquals(1, statement.getAttributes().size(), "expected exactly one attribute");
        return statement.getAttributes().get(0).getAttribute();
    }

    private static String decodedXml(AttributeStatementType statement) {
        List<Object> values = onlyAttribute(statement).getAttributeValue();
        assertEquals(1, values.size(), "expected exactly one attribute value");
        return new String(Base64.getDecoder().decode((String) values.get(0)), StandardCharsets.UTF_8);
    }

    /** "scope -> privilege" pairs in the emitted list, for order-insensitive checks. */
    private static Set<String> pairs(String xml) {
        return java.util.regex.Pattern.compile(
                        "<PrivilegeGroup Scope=\"([^\"]+)\">(.*?)</PrivilegeGroup>")
                .matcher(xml)
                .results()
                .flatMap(group -> java.util.regex.Pattern.compile("<Privilege>(.*?)</Privilege>")
                        .matcher(group.group(2))
                        .results()
                        .map(p -> group.group(1).substring(SCOPE.length()) + " -> " + p.group(1)))
                .collect(Collectors.toSet());
    }

    // --- registration and config -------------------------------------------

    @Test
    void identifiesItselfAsASamlMapper() {
        assertEquals("oiosaml3-privileges-saml-protocol-mapper", mapper.getId());
        assertEquals("saml", mapper.getProtocol());
        assertEquals(AttributeStatementHelper.ATTRIBUTE_STATEMENT_CATEGORY, mapper.getDisplayCategory());
    }

    @Test
    void acceptsAnEightDigitAuthorityCvr() {
        assertDoesNotThrow(() -> mapper.validateConfig(null, null, null, model(defaults())));
    }

    @Test
    void rejectsAMissingOrMalformedAuthorityCvr() {
        for (String cvr : new String[] {null, "", "1234567", "123456789", "abcdefgh"}) {
            Map<String, String> config = defaults();
            config.put(OioSaml3PrivilegesProtocolMapper.CONF_SCOPE_CVR, cvr);
            ProtocolMapperConfigException e = assertThrows(
                    ProtocolMapperConfigException.class,
                    () -> mapper.validateConfig(null, null, null, model(config)),
                    "cvr " + cvr);
            // Keycloak's admin API fails with a NullPointerException on a null key.
            assertNotNull(e.getMessageKey(), "message key for cvr " + cvr);
        }
    }

    @Test
    void acceptsAnAuthorityCvrWithSurroundingWhitespace() {
        Map<String, String> config = defaults();
        config.put(OioSaml3PrivilegesProtocolMapper.CONF_SCOPE_CVR, " " + CVR + " ");
        assertDoesNotThrow(() -> mapper.validateConfig(null, null, null, model(config)));
    }

    // --- emitting the attribute --------------------------------------------

    @Test
    void omitsTheAttributeForAUserWithoutGroups() {
        assertTrue(run(defaults(), session("hans")).getAttributes().isEmpty());
    }

    @Test
    void omitsTheAttributeWhenNoGroupCarriesARole() {
        Group plain = group("plain").attr("something.else", "x");
        assertTrue(run(defaults(), session("hans", plain)).getAttributes().isEmpty());
    }

    @Test
    void emitsTheRoleOfAGroupUnderTheConfiguredName() {
        Group group = group("sagsbehandlere").attr(ROLE_ATTR, ROLE_A);

        AttributeStatementType statement = run(defaults(), session("hans", group));

        AttributeType attribute = onlyAttribute(statement);
        assertEquals(OioSaml3PrivilegesProtocolMapper.DEFAULT_ATTRIBUTE_NAME, attribute.getName());
        assertEquals("urn:oasis:names:tc:SAML:2.0:attrname-format:uri", attribute.getNameFormat());
        assertEquals(
                new PrivilegeListBuilder(PrivilegeListBuilder.NAMESPACE_DIGST).add(CVR, ROLE_A).toXml(),
                decodedXml(statement));
    }

    @Test
    void honoursTheOioSaml2NameAndFormat() {
        Map<String, String> config = defaults();
        config.put(AttributeStatementHelper.SAML_ATTRIBUTE_NAME, "dk:gov:saml:attribute:Privileges_intermediate");
        config.put(AttributeStatementHelper.SAML_ATTRIBUTE_NAMEFORMAT, AttributeStatementHelper.BASIC);
        config.put(AttributeStatementHelper.FRIENDLY_NAME, "Privileges");

        AttributeType attribute =
                onlyAttribute(run(config, session("hans", group("g").attr(ROLE_ATTR, ROLE_A))));

        assertEquals("dk:gov:saml:attribute:Privileges_intermediate", attribute.getName());
        assertEquals("urn:oasis:names:tc:SAML:2.0:attrname-format:basic", attribute.getNameFormat());
        assertEquals("Privileges", attribute.getFriendlyName());
    }

    @Test
    void emitsEveryValueOfAMultiValuedGroupAttribute() {
        Group group = group("g").attr(ROLE_ATTR, ROLE_A, ROLE_B);

        assertEquals(
                Set.of(CVR + " -> " + ROLE_A, CVR + " -> " + ROLE_B),
                pairs(decodedXml(run(defaults(), session("hans", group)))));
    }

    @Test
    void mergesRolesFromSeveralGroupsWithoutDuplicates() {
        Group a = group("a").attr(ROLE_ATTR, ROLE_A);
        Group b = group("b").attr(ROLE_ATTR, ROLE_A, ROLE_B);

        String xml = decodedXml(run(defaults(), session("hans", a, b)));

        assertEquals(Set.of(CVR + " -> " + ROLE_A, CVR + " -> " + ROLE_B), pairs(xml));
        assertEquals(1, xml.split("<PrivilegeGroup ", -1).length - 1, "one scope, one group");
    }

    @Test
    void scopesADelegatedGroupToTheDelegatingAuthority() {
        Group own = group("own").attr(ROLE_ATTR, ROLE_A);
        Group delegated = group("delegated").attr(ROLE_ATTR, ROLE_C).attr(SCOPE_ATTR, " " + OTHER_CVR + " ");

        assertEquals(
                Set.of(CVR + " -> " + ROLE_A, OTHER_CVR + " -> " + ROLE_C),
                pairs(decodedXml(run(defaults(), session("hans", own, delegated)))));
    }

    @Test
    void fallsBackToTheAuthorityCvrWhenTheDelegationAttributeIsBlank() {
        Group group = group("g").attr(ROLE_ATTR, ROLE_A).attr(SCOPE_ATTR, "  ");

        assertEquals(
                Set.of(CVR + " -> " + ROLE_A),
                pairs(decodedXml(run(defaults(), session("hans", group)))));
    }

    @Test
    void ignoresDelegationWhenTheDelegationAttributeIsNotConfigured() {
        Map<String, String> config = defaults();
        config.remove(OioSaml3PrivilegesProtocolMapper.CONF_GROUP_SCOPE_ATTRIBUTE);
        Group group = group("g").attr(ROLE_ATTR, ROLE_A).attr(SCOPE_ATTR, OTHER_CVR);

        assertEquals(Set.of(CVR + " -> " + ROLE_A), pairs(decodedXml(run(config, session("hans", group)))));
    }

    @Test
    void includesRolesOnParentGroupsByDefault() {
        Group parent = group("forvaltning").attr(ROLE_ATTR, ROLE_A);
        Group child = parent.child("team").attr(ROLE_ATTR, ROLE_B);

        assertEquals(
                Set.of(CVR + " -> " + ROLE_A, CVR + " -> " + ROLE_B),
                pairs(decodedXml(run(defaults(), session("hans", child)))));
    }

    @Test
    void parentGroupsUseTheirOwnDelegationNotTheChildsOne() {
        Group parent = group("parent").attr(ROLE_ATTR, ROLE_A);
        Group child = parent.child("child").attr(ROLE_ATTR, ROLE_C).attr(SCOPE_ATTR, OTHER_CVR);

        assertEquals(
                Set.of(CVR + " -> " + ROLE_A, OTHER_CVR + " -> " + ROLE_C),
                pairs(decodedXml(run(defaults(), session("hans", child)))));
    }

    @Test
    void skipsParentGroupsWhenDisabled() {
        Map<String, String> config = defaults();
        config.put(OioSaml3PrivilegesProtocolMapper.CONF_INCLUDE_PARENTS, "false");
        Group parent = group("forvaltning").attr(ROLE_ATTR, ROLE_A);
        Group child = parent.child("team").attr(ROLE_ATTR, ROLE_B);

        assertEquals(Set.of(CVR + " -> " + ROLE_B), pairs(decodedXml(run(config, session("hans", child)))));
    }

    @Test
    void visitsASharedAncestorOnlyOnce() {
        Group root = group("root").attr(ROLE_ATTR, ROLE_A);
        Group left = root.child("left");
        Group right = root.child("right").attr(ROLE_ATTR, ROLE_B);

        String xml = decodedXml(run(defaults(), session("hans", left, right, root)));

        assertEquals(Set.of(CVR + " -> " + ROLE_A, CVR + " -> " + ROLE_B), pairs(xml));
        assertEquals(1, xml.split(ROLE_A, -1).length - 1);
    }

    @Test
    void readsRolesFromACustomGroupAttribute() {
        Map<String, String> config = defaults();
        config.put(OioSaml3PrivilegesProtocolMapper.CONF_GROUP_ATTRIBUTE, "kombit.role");
        Group group = group("g").attr("kombit.role", ROLE_B).attr(ROLE_ATTR, ROLE_A);

        assertEquals(Set.of(CVR + " -> " + ROLE_B), pairs(decodedXml(run(config, session("hans", group)))));
    }

    @Test
    void fallsBackToTheDefaultGroupAttributeWhenItsConfigIsBlank() {
        Map<String, String> config = defaults();
        config.put(OioSaml3PrivilegesProtocolMapper.CONF_GROUP_ATTRIBUTE, " ");

        assertEquals(
                Set.of(CVR + " -> " + ROLE_A),
                pairs(decodedXml(run(config, session("hans", group("g").attr(ROLE_ATTR, ROLE_A))))));
    }

    @Test
    void usesTheLegacyNamespaceWhenSelected() {
        Map<String, String> config = defaults();
        config.put(
                OioSaml3PrivilegesProtocolMapper.CONF_NAMESPACE,
                OioSaml3PrivilegesProtocolMapper.NAMESPACE_OPTION_ITST);

        String xml = decodedXml(run(config, session("hans", group("g").attr(ROLE_ATTR, ROLE_A))));

        assertTrue(xml.contains("xmlns:bpp=\"" + PrivilegeListBuilder.NAMESPACE_ITST + "\""), xml);
    }

    @Test
    void aMisconfiguredGroupDoesNotCostTheUserTheirOtherRoles() {
        Group good = group("good").attr(ROLE_ATTR, ROLE_A);
        Group badCvr = group("bad-cvr").attr(ROLE_ATTR, ROLE_B).attr(SCOPE_ATTR, "not-a-cvr");
        Group blankUri = group("blank-uri").attr(ROLE_ATTR, "  ", ROLE_C);

        assertEquals(
                Set.of(CVR + " -> " + ROLE_A, CVR + " -> " + ROLE_C),
                pairs(decodedXml(run(defaults(), session("hans", good, badCvr, blankUri)))));
    }

    @Test
    void omitsTheAttributeWhenEveryRoleIsInvalid() {
        Group badCvr = group("bad-cvr").attr(ROLE_ATTR, ROLE_B).attr(SCOPE_ATTR, "1234");

        assertTrue(run(defaults(), session("hans", badCvr)).getAttributes().isEmpty());
    }
}
