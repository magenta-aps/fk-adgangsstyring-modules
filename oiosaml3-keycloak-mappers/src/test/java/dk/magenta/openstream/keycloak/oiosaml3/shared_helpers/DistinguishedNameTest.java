// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.shared_helpers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DistinguishedNameTest {

    /** The DN the mock IdP asserts, copied from config/authsources.php. */
    private static final String DN =
            "C=DK,O=11715311,CN=Hans Hansen,Serial=74c08b2b-212b-4f6d-9ce6-0fba1651087d";

    @Test
    void parsesTheMockIdpDn() {
        DistinguishedName dn = DistinguishedName.parse(DN);

        assertEquals("74c08b2b-212b-4f6d-9ce6-0fba1651087d", dn.get("Serial"));
        assertEquals("Hans Hansen", dn.get("CN"));
        assertEquals("11715311", dn.get("O"));
        assertEquals("DK", dn.get("C"));
    }

    @Test
    void componentLookupIgnoresCase() {
        DistinguishedName dn = DistinguishedName.parse(DN);

        assertEquals(dn.get("Serial"), dn.get("serial"));
        assertEquals(dn.get("CN"), dn.get("cn"));
        // A DN that spells it with the registered X.500 type name still resolves.
        assertEquals(
                "abc",
                DistinguishedName.parse("CN=Someone,SERIALNUMBER=abc").get("Serial"));
    }

    @Test
    void surnameIsNotTreatedAsTheSerial() {
        // SN is surname in X.500. Reading it as the serial would key the
        // identity on the person's name — the thing Serial exists to avoid.
        assertNull(DistinguishedName.parse("CN=Hans Hansen,SN=Hansen").get("Serial"));
    }

    @Test
    void handlesEscapedAndQuotedCommasInNames() {
        DistinguishedName escaped =
                DistinguishedName.parse("CN=Hansen\\, Hans,Serial=abc,O=11715311");
        assertEquals("Hansen, Hans", escaped.get("CN"));
        assertEquals("abc", escaped.get("Serial"));

        DistinguishedName quoted = DistinguishedName.parse("CN=\"Hansen, Hans\",Serial=abc");
        assertEquals("Hansen, Hans", quoted.get("CN"));
        assertEquals("abc", quoted.get("Serial"));
    }

    @Test
    void toleratesWhitespaceAndMissingComponents() {
        DistinguishedName dn = DistinguishedName.parse(" C=DK , CN=Hans Hansen ");

        assertEquals("Hans Hansen", dn.get("CN"));
        assertNull(dn.get("Serial"));
        assertTrue(DistinguishedName.parse(null).isEmpty());
        assertTrue(DistinguishedName.parse("   ").isEmpty());
        assertTrue(DistinguishedName.parse("garbage-without-equals").isEmpty());
    }

    @Test
    void parsesRfc4514EscapedValues() {
        DistinguishedName dn = DistinguishedName.parse(
                "C=DK,O=11715311,CN=O'Brien\\, \\\"Bo\\\" \\+ \\<Hans\\>\\; Back\\\\slash,Serial=abc\\,def");

        assertEquals("O'Brien, \"Bo\" + <Hans>; Back\\slash", dn.get("CN"));
        assertEquals("abc,def", dn.get("Serial"));
        assertEquals("11715311", dn.get("O"));
    }
}
