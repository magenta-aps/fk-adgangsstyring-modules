// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.shared_helpers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dk.magenta.openstream.keycloak.oiosaml3.shared_helpers.PrivilegeList.Constraint;
import dk.magenta.openstream.keycloak.oiosaml3.shared_helpers.PrivilegeList.PrivilegeGroup;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

class PrivilegeListTest {

    static final String DIGST = PrivilegeListBuilder.NAMESPACE_DIGST;

    static String encode(String xml) {
        return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    }

    static String list(String namespace, String groups) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<bpp:PrivilegeList xmlns:bpp=\"" + namespace + "\""
                + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
                + groups
                + "</bpp:PrivilegeList>";
    }

    /** What Context Handler sent the test SP, from bpp-example.xml. */
    private static final String FROM_CONTEXT_HANDLER =
            list(
                    DIGST,
                    "<PrivilegeGroup Scope=\"urn:dk:gov:saml:cvrNumberIdentifier:25052943\">"
                            + "<Privilege>http://test.openstream.dk/roles/usersystemrole/org_admin/1</Privilege>"
                            + "</PrivilegeGroup>"
                            + "<PrivilegeGroup Scope=\"urn:dk:gov:saml:cvrNumberIdentifier:25052943\">"
                            + "<Privilege>http://test.openstream.dk/roles/usersystemrole/org_user/1</Privilege>"
                            + "</PrivilegeGroup>");

    @Test
    void parsesAContextHandlerValue() {
        List<PrivilegeGroup> groups = PrivilegeList.parse(encode(FROM_CONTEXT_HANDLER));

        assertEquals(2, groups.size());
        assertEquals("urn:dk:gov:saml:cvrNumberIdentifier:25052943", groups.get(0).scope());
        assertEquals("25052943", groups.get(0).scopeCvr());
        assertEquals(
                List.of("http://test.openstream.dk/roles/usersystemrole/org_admin/1"),
                groups.get(0).privileges());
        assertTrue(groups.get(0).constraints().isEmpty());
    }

    @Test
    void parsesTheProfilesConstraintExample() {
        // KOMBIT profile section 1.6, including the stray space in the second
        // Name and the itst.dk namespace the profile's examples use.
        String xml =
                list(
                        PrivilegeListBuilder.NAMESPACE_ITST,
                        "<PrivilegeGroup Scope=\"urn:dk:gov:saml:cvrNumberIdentifier:20374826\">"
                                + "<Constraint Name=\"http://sts.kombit.dk/constraint/kle/1\">25.*</Constraint>"
                                + "<Constraint Name=\" http://sts.kombit.dk/constraint/foelsomhed/1\">Medium</Constraint>"
                                + "<Privilege>http://sapa.kombit.dk/roles/usersystemrole/se_sag/1</Privilege>"
                                + "</PrivilegeGroup>");

        PrivilegeGroup group = PrivilegeList.parse(encode(xml)).get(0);

        assertEquals(
                List.of(
                        new Constraint("http://sts.kombit.dk/constraint/kle/1", "25.*"),
                        new Constraint("http://sts.kombit.dk/constraint/foelsomhed/1", "Medium")),
                group.constraints());
        assertEquals(
                List.of("http://sapa.kombit.dk/roles/usersystemrole/se_sag/1"), group.privileges());
    }

    @Test
    void trimsWhitespaceAroundPrivilegeUris() {
        // The profile's jobfunktionsrolle example breaks the line before </Privilege>.
        String xml =
                list(
                        DIGST,
                        "<PrivilegeGroup Scope=\"urn:dk:gov:saml:cvrNumberIdentifier:20374826\">"
                                + "<Privilege>http://odense.dk/roles/jobrole/leder/1\n    </Privilege>"
                                + "</PrivilegeGroup>");

        assertEquals(
                List.of("http://odense.dk/roles/jobrole/leder/1"),
                PrivilegeList.parse(encode(xml)).get(0).privileges());
    }

    @Test
    void onlyACvrNumberIdentifierScopeHasACvr() {
        assertEquals(
                "12345678",
                new PrivilegeGroup("urn:dk:gov:saml:cvrNumberIdentifier:12345678", List.of(), List.of())
                        .scopeCvr());
        assertNull(
                new PrivilegeGroup("urn:dk:gov:saml:productionUnitIdentifier:12345678", List.of(), List.of())
                        .scopeCvr());
        assertNull(
                new PrivilegeGroup("urn:dk:gov:saml:cvrNumberIdentifier:1234", List.of(), List.of())
                        .scopeCvr());
        assertNull(new PrivilegeGroup(null, List.of(), List.of()).scopeCvr());
    }

    @Test
    void aGroupWithoutScopeIsKeptWithANullScope() {
        String xml = list(DIGST, "<PrivilegeGroup><Privilege>urn:x</Privilege></PrivilegeGroup>");

        PrivilegeGroup group = PrivilegeList.parse(encode(xml)).get(0);

        assertNull(group.scope());
        assertNull(group.scopeCvr());
    }

    @Test
    void readsWhatTheProtocolMapperWrites() {
        String encoded =
                new PrivilegeListBuilder(DIGST)
                        .add("29189846", "http://kombit.dk/roles/jobrole/sagsbehandler/1")
                        .add("12345678", "http://kombit.dk/roles/jobrole/delegeret/1")
                        .toBase64();

        List<PrivilegeGroup> groups = PrivilegeList.parse(encoded);

        assertEquals(List.of("29189846", "12345678"), groups.stream().map(PrivilegeGroup::scopeCvr).toList());
        assertEquals(
                List.of("http://kombit.dk/roles/jobrole/sagsbehandler/1"), groups.get(0).privileges());
    }

    @Test
    void toleratesWhitespaceInBase64() {
        String value = encode(FROM_CONTEXT_HANDLER);
        assertEquals(
                2, PrivilegeList.parse(value.substring(0, 40) + "\n  " + value.substring(40)).size());
    }

    @Test
    void rejectsAnythingButAnOioBppPrivilegeList() {
        assertThrows(
                PrivilegeList.PrivilegeParseException.class, () -> PrivilegeList.parse("not-base64!"));
        assertThrows(
                PrivilegeList.PrivilegeParseException.class,
                () -> PrivilegeList.parse(encode("<unclosed>")));
        assertThrows(
                PrivilegeList.PrivilegeParseException.class,
                () -> PrivilegeList.parse(encode("<PrivilegeList/>")),
                "a PrivilegeList outside the bpp namespace is not OIO-BPP");
        assertThrows(
                PrivilegeList.PrivilegeParseException.class,
                () -> PrivilegeList.parse(encode("<bpp:Other xmlns:bpp=\"" + DIGST + "\"/>")));
    }

    @Test
    void rejectsExternalEntities() {
        // An IdP-supplied blob must not be able to read files off the server.
        String xxe =
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                        + "<bpp:PrivilegeList xmlns:bpp=\"" + DIGST + "\">"
                        + "<PrivilegeGroup Scope=\"s\"><Privilege>&xxe;</Privilege></PrivilegeGroup>"
                        + "</bpp:PrivilegeList>";

        assertThrows(
                PrivilegeList.PrivilegeParseException.class, () -> PrivilegeList.parse(encode(xxe)));
    }
}
