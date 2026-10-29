// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.leverandor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;

class OioSaml3SubjectMapperTest {

    private static String subjectId(String dn) {
        return OioSaml3SubjectMapper.subjectId(TestAssertions.context(dn, Map.of()));
    }

    @Test
    void keysOnCvrAndSerial() {
        assertEquals("11715311_74c08b2b-212b-4f6d-9ce6-0fba1651087d", subjectId(TestAssertions.DN));
    }

    @Test
    void theSameSerialInTwoAuthoritiesIsTwoPeople() {
        // Serial is only unique within the authority, so this must not
        // collapse into one account.
        assertNotEquals(
                subjectId("C=DK,O=11111111,CN=Hans Hansen,Serial=1234"),
                subjectId("C=DK,O=22222222,CN=Hans Hansen,Serial=1234"));
    }

    @Test
    void survivesANameChange() {
        assertEquals(
                subjectId(TestAssertions.DN),
                subjectId(
                        "C=DK,O=11715311,CN=Hans Peter Bang Nielsen,"
                                + "Serial=74c08b2b-212b-4f6d-9ce6-0fba1651087d"));
    }

    @Test
    void ignoresThePersistentUuidAttribute() {
        // The profile does not tie uuid/persistent to the Serial; reading it
        // would let the key switch between logins.
        var context =
                TestAssertions.context(
                        TestAssertions.DN,
                        Map.of(
                                "https://data.gov.dk/model/core/eid/professional/uuid/persistent",
                                "00000000-0000-0000-0000-000000000000"));
        assertEquals(
                "11715311_74c08b2b-212b-4f6d-9ce6-0fba1651087d",
                OioSaml3SubjectMapper.subjectId(context));
    }

    @Test
    void failsTheLoginWithoutAUsableDn() {
        assertThrows(IdentityBrokerException.class, () -> subjectId("C=DK,CN=Hans,Serial=1"));
        assertThrows(IdentityBrokerException.class, () -> subjectId("C=DK,O=1171531,Serial=1"));
        assertThrows(IdentityBrokerException.class, () -> subjectId("C=DK,O=11715311,CN=Hans"));
        assertThrows(
                IdentityBrokerException.class,
                () -> OioSaml3SubjectMapper.subjectId(TestAssertions.context(null, Map.of())));
    }

    @Test
    void readsOnlyAnX509SubjectNameNameId() {
        var persistent =
                TestAssertions.context(
                        TestAssertions.DN,
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                        Map.of());
        assertThrows(
                IdentityBrokerException.class, () -> OioSaml3SubjectMapper.subjectId(persistent));
    }

    @Test
    void doesNotReadTheDnFromAnAttribute() {
        // The oiosamlDN attribute is a mock-IdP artefact, not part of the profile.
        var context = TestAssertions.context(null, Map.of("oiosamlDN", TestAssertions.DN));
        assertThrows(IdentityBrokerException.class, () -> OioSaml3SubjectMapper.subjectId(context));
    }
}
