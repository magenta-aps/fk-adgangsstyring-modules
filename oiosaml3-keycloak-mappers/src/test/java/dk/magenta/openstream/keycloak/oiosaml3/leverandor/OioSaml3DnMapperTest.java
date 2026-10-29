// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.leverandor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class OioSaml3DnMapperTest {

    @Test
    void transformsSplitACommonNameIntoGivenAndFamilyName() {
        assertEquals("Hans",
                OioSaml3DnMapper.transform("Hans Hansen", OioSaml3DnMapper.TRANSFORM_FIRST_WORD));
        assertEquals("Hansen",
                OioSaml3DnMapper.transform("Hans Hansen", OioSaml3DnMapper.TRANSFORM_REST));
        assertEquals("Peter Bang Hansen",
                OioSaml3DnMapper.transform(
                        "Hans Peter Bang Hansen", OioSaml3DnMapper.TRANSFORM_REST));
        // A one-word CN has no family name to give; keep the value rather than
        // writing an empty last name.
        assertEquals("Hans", OioSaml3DnMapper.transform("Hans", OioSaml3DnMapper.TRANSFORM_REST));
        assertEquals("Hans Hansen",
                OioSaml3DnMapper.transform("Hans Hansen", OioSaml3DnMapper.TRANSFORM_NONE));
    }
}
