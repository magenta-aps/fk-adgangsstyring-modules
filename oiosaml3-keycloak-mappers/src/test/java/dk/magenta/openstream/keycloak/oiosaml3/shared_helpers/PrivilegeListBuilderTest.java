// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.shared_helpers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dk.magenta.openstream.keycloak.oiosaml3.shared_helpers.PrivilegeList.Constraint;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

class PrivilegeListBuilderTest {

    private static final String DIGST = PrivilegeListBuilder.NAMESPACE_DIGST;
    private static final String PROLOG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
    private static final String OPEN =
            "<bpp:PrivilegeList xmlns:bpp=\"" + DIGST + "\""
                    + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">";
    private static final String CLOSE = "</bpp:PrivilegeList>";
    private static final String SCOPE = "urn:dk:gov:saml:cvrNumberIdentifier:";

    private static final String ROLE_A = "http://kombit.dk/roles/jobrole/sagsbehandler/1";
    private static final String ROLE_B = "http://kombit.dk/roles/jobrole/leder/1";
    private static final String KLE = "http://kommune.dk/KLE-SEK/1/parametric";
    private static final String ORG = "http://kommune.dk/ORG/1/parametric";

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        return factory.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void startsEmpty() {
        assertTrue(new PrivilegeListBuilder(DIGST).isEmpty());
    }

    @Test
    void writesOnePrivilegeExactly() {
        String xml = new PrivilegeListBuilder(DIGST).add("29189846", ROLE_A).toXml();

        assertEquals(
                PROLOG + OPEN
                        + "<PrivilegeGroup Scope=\"" + SCOPE + "29189846\">"
                        + "<Privilege>" + ROLE_A + "</Privilege>"
                        + "</PrivilegeGroup>"
                        + CLOSE,
                xml);
    }

    @Test
    void writesOneGroupPerPrivilegeInInsertionOrder() {
        // KOMBIT: "1 PrivilegeGroup = 1 jobfunktionsrolle", even for the same scope.
        String xml =
                new PrivilegeListBuilder(DIGST)
                        .add("29189846", ROLE_A)
                        .add("12345678", ROLE_B)
                        .add("29189846", ROLE_B)
                        .toXml();

        assertEquals(
                PROLOG + OPEN
                        + "<PrivilegeGroup Scope=\"" + SCOPE + "29189846\">"
                        + "<Privilege>" + ROLE_A + "</Privilege>"
                        + "</PrivilegeGroup>"
                        + "<PrivilegeGroup Scope=\"" + SCOPE + "12345678\">"
                        + "<Privilege>" + ROLE_B + "</Privilege>"
                        + "</PrivilegeGroup>"
                        + "<PrivilegeGroup Scope=\"" + SCOPE + "29189846\">"
                        + "<Privilege>" + ROLE_B + "</Privilege>"
                        + "</PrivilegeGroup>"
                        + CLOSE,
                xml);
    }

    @Test
    void collapsesDuplicatePrivilegesWithinAScope() {
        String xml =
                new PrivilegeListBuilder(DIGST)
                        .add("29189846", ROLE_A)
                        .add("29189846", ROLE_A)
                        .add(" 29189846 ", " " + ROLE_A + " ")
                        .toXml();

        assertEquals(1, xml.split("<Privilege>", -1).length - 1);
        assertEquals(1, xml.split("<PrivilegeGroup ", -1).length - 1);
    }

    @Test
    void keepsTheSamePrivilegeForDifferentScopes() {
        String xml =
                new PrivilegeListBuilder(DIGST)
                        .add("29189846", ROLE_A)
                        .add("12345678", ROLE_A)
                        .toXml();

        assertEquals(2, xml.split("<PrivilegeGroup ", -1).length - 1);
    }

    @Test
    void trimsCvrAndUri() {
        String xml = new PrivilegeListBuilder(DIGST).add(" 29189846\n", "\t" + ROLE_A + " ").toXml();

        assertTrue(xml.contains("Scope=\"" + SCOPE + "29189846\""));
        assertTrue(xml.contains("<Privilege>" + ROLE_A + "</Privilege>"));
    }

    @Test
    void containsNoWhitespaceBetweenElements() {
        String xml =
                new PrivilegeListBuilder(DIGST)
                        .add("29189846", ROLE_A)
                        .add("12345678", ROLE_B)
                        .toXml();

        assertFalse(xml.contains("\n"));
        assertFalse(xml.contains("> <"));
        assertFalse(xml.contains(">\t<"));
    }

    @Test
    void rejectsInvalidCvr() {
        PrivilegeListBuilder builder = new PrivilegeListBuilder(DIGST);
        for (String cvr : new String[] {null, "", "   ", "1234567", "123456789", "1234567a", "12 345678"}) {
            assertThrows(IllegalArgumentException.class, () -> builder.add(cvr, ROLE_A), "cvr " + cvr);
        }
        assertTrue(builder.isEmpty());
    }

    @Test
    void rejectsBlankUri() {
        PrivilegeListBuilder builder = new PrivilegeListBuilder(DIGST);
        assertThrows(IllegalArgumentException.class, () -> builder.add("29189846", null));
        assertThrows(IllegalArgumentException.class, () -> builder.add("29189846", ""));
        assertThrows(IllegalArgumentException.class, () -> builder.add("29189846", "  "));
        assertTrue(builder.isEmpty());
    }

    @Test
    void escapesXmlSpecialCharacters() throws Exception {
        String uri = "http://x/roles?a=1&b=<2>\"'";
        String xml = new PrivilegeListBuilder(DIGST).add("29189846", uri).toXml();

        assertTrue(xml.contains("<Privilege>http://x/roles?a=1&amp;b=&lt;2&gt;&quot;&apos;</Privilege>"));
        assertEquals(uri, parse(xml).getElementsByTagName("Privilege").item(0).getTextContent());
    }

    @Test
    void qualifiesOnlyPrivilegeListWithTheBppNamespace() throws Exception {
        Document doc = parse(new PrivilegeListBuilder(DIGST).add("29189846", ROLE_A).toXml());

        Element list = doc.getDocumentElement();
        assertEquals(DIGST, list.getNamespaceURI());
        assertEquals("PrivilegeList", list.getLocalName());

        Element group = (Element) list.getFirstChild();
        assertNull(group.getNamespaceURI());
        assertEquals("PrivilegeGroup", group.getLocalName());
        assertEquals(SCOPE + "29189846", group.getAttribute("Scope"));

        Element privilege = (Element) group.getFirstChild();
        assertNull(privilege.getNamespaceURI());
        assertEquals("Privilege", privilege.getLocalName());
        assertEquals(ROLE_A, privilege.getTextContent());
    }

    @Test
    void usesTheLegacyNamespaceWhenAsked() throws Exception {
        String xml =
                new PrivilegeListBuilder(PrivilegeListBuilder.NAMESPACE_ITST)
                        .add("29189846", ROLE_A)
                        .toXml();

        assertEquals(
                "http://itst.dk/oiosaml/basic_privilege_profile",
                parse(xml).getDocumentElement().getNamespaceURI());
    }

    @Test
    void base64IsTheUtf8EncodedXml() {
        PrivilegeListBuilder builder =
                new PrivilegeListBuilder(DIGST).add("29189846", "http://x/roles/æøå/1");

        byte[] decoded = Base64.getDecoder().decode(builder.toBase64());

        assertEquals(builder.toXml(), new String(decoded, StandardCharsets.UTF_8));
        assertFalse(builder.toBase64().contains("\n"));
    }

    @Test
    void validatesCvrNumbers() {
        assertTrue(PrivilegeListBuilder.isValidCvr("29189846"));
        assertFalse(PrivilegeListBuilder.isValidCvr(null));
        assertFalse(PrivilegeListBuilder.isValidCvr(""));
        assertFalse(PrivilegeListBuilder.isValidCvr("2918984"));
        assertFalse(PrivilegeListBuilder.isValidCvr(" 29189846"));
        assertFalse(PrivilegeListBuilder.isValidCvr("2918984x"));
    }

    // --- constraints --------------------------------------------------------

    @Test
    void writesConstraintsAfterThePrivilege() {
        String xml = new PrivilegeListBuilder(DIGST)
                .add("29189846", ROLE_A, List.of(new Constraint(KLE, "25.*,27.10.*"), new Constraint(ORG, "abc")))
                .toXml();

        assertEquals(
                PROLOG + OPEN
                        + "<PrivilegeGroup Scope=\"" + SCOPE + "29189846\">"
                        + "<Privilege>" + ROLE_A + "</Privilege>"
                        + "<Constraint Name=\"" + KLE + "\">25.*,27.10.*</Constraint>"
                        + "<Constraint Name=\"" + ORG + "\">abc</Constraint>"
                        + "</PrivilegeGroup>"
                        + CLOSE,
                xml);
    }

    @Test
    void normalisesConstraintValueLists() {
        String xml = new PrivilegeListBuilder(DIGST)
                .add("29189846", ROLE_A, List.of(new Constraint(" " + KLE + " ", " 25.* , ,27.*,25.* ")))
                .toXml();

        assertTrue(xml.contains("<Constraint Name=\"" + KLE + "\">25.*,27.*</Constraint>"), xml);
    }

    @Test
    void mergesConstraintsWhenTheSamePrivilegeIsAddedAgain() {
        String xml = new PrivilegeListBuilder(DIGST)
                .add("29189846", ROLE_A, List.of(new Constraint(KLE, "25.*")))
                .add("29189846", ROLE_A)
                .add("29189846", ROLE_A, List.of(new Constraint(KLE, "27.*,25.*"), new Constraint(ORG, "x")))
                .toXml();

        assertEquals(1, xml.split("<PrivilegeGroup ", -1).length - 1);
        assertTrue(xml.contains("<Constraint Name=\"" + KLE + "\">25.*,27.*</Constraint>"), xml);
        assertTrue(xml.contains("<Constraint Name=\"" + ORG + "\">x</Constraint>"), xml);
    }

    @Test
    void keepsConstraintsOfDifferentScopesApart() {
        String xml = new PrivilegeListBuilder(DIGST)
                .add("29189846", ROLE_A, List.of(new Constraint(KLE, "25.*")))
                .add("12345678", ROLE_A)
                .toXml();

        assertTrue(xml.endsWith(
                "<PrivilegeGroup Scope=\"" + SCOPE + "12345678\">"
                        + "<Privilege>" + ROLE_A + "</Privilege>"
                        + "</PrivilegeGroup>"
                        + CLOSE),
                xml);
    }

    @Test
    void dropsAConstraintWithoutValues() {
        String xml = new PrivilegeListBuilder(DIGST)
                .add("29189846", ROLE_A, List.of(new Constraint(KLE, " , "), new Constraint(ORG, null)))
                .toXml();

        assertFalse(xml.contains("<Constraint"), xml);
        assertTrue(xml.contains("<Privilege>" + ROLE_A + "</Privilege>"));
    }

    @Test
    void rejectsABlankConstraintNameWithoutAddingAnything() {
        PrivilegeListBuilder builder = new PrivilegeListBuilder(DIGST);
        for (String name : new String[] {null, "", "  "}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> builder.add("29189846", ROLE_A, List.of(new Constraint(name, "25.*"))),
                    "name " + name);
        }
        assertTrue(builder.isEmpty());
    }

    @Test
    void escapesConstraintNamesAndValues() throws Exception {
        String xml = new PrivilegeListBuilder(DIGST)
                .add("29189846", ROLE_A, List.of(new Constraint("http://x/p?a=1&b=\"2\"", "<a>&b")))
                .toXml();

        Element constraint = (Element) parse(xml).getElementsByTagName("Constraint").item(0);
        assertEquals("http://x/p?a=1&b=\"2\"", constraint.getAttribute("Name"));
        assertEquals("<a>&b", constraint.getTextContent());
        assertNull(constraint.getNamespaceURI());
    }

    @Test
    void outputParsesBackWithItsConstraints() {
        String base64 = new PrivilegeListBuilder(DIGST)
                .add("29189846", ROLE_A, List.of(new Constraint(KLE, "25.*")))
                .toBase64();

        List<PrivilegeList.PrivilegeGroup> groups = PrivilegeList.parse(base64);

        assertEquals(1, groups.size());
        assertEquals(List.of(ROLE_A), groups.get(0).privileges());
        assertEquals(List.of(new Constraint(KLE, "25.*")), groups.get(0).constraints());
    }

    @Test
    void normalisedValuesStillMatchAListSyntaxRegex() throws Exception {
        // A real constraint type: http://test.openworkplace.dk/constraints/site_uid/1,
        // "Syntaksvalidering" with this regex in Administrationsmodulet.
        java.util.regex.Pattern siteUid = java.util.regex.Pattern.compile("^[-a-z0-9]+(,[-a-z0-9]+)*$");
        String name = "http://test.openworkplace.dk/constraints/site_uid/1/parametric";

        String[][] cases = {
            // value(s) added for the same role,  expected value sent
            {"site-a", "site-a"},
            {"site-a,site-b", "site-a,site-b"},
            {" site-a , site-b ", "site-a,site-b"},
            {",site-a,,site-b,", "site-a,site-b"},
            {"site-a,site-a", "site-a"},
            {"site-a|site-b,site-a|site-c", "site-a,site-b,site-c"},
        };
        for (String[] c : cases) {
            PrivilegeListBuilder builder = new PrivilegeListBuilder(DIGST);
            for (String value : c[0].split("\\|")) {
                builder.add("29189846", ROLE_A, List.of(new Constraint(name, value)));
            }
            String sent = ((Element) parse(builder.toXml()).getElementsByTagName("Constraint").item(0))
                    .getTextContent();

            assertEquals(c[1], sent, "input " + c[0]);
            assertTrue(siteUid.matcher(sent).matches(), "regex rejects '" + sent + "' from " + c[0]);
        }
    }
}
