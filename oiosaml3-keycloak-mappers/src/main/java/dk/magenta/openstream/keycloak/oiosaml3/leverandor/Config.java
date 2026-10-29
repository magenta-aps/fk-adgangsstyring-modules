// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.leverandor;

import java.util.Map;
import org.keycloak.models.IdentityProviderMapperModel;

/**
 * Mapper config access. Blank is treated as unset throughout: the admin
 * console writes an empty string for a field the operator cleared, and the
 * difference between "" and absent is never one a mapper wants to act on.
 */
final class Config {

    private Config() {}

    static String string(IdentityProviderMapperModel mapperModel, String key) {
        Map<String, String> config = mapperModel.getConfig();
        if (config == null) {
            return null;
        }
        String value = config.get(key);
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
