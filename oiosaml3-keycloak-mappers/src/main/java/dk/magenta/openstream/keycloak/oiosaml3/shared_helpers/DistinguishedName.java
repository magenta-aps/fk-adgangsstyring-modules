// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.shared_helpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The OIOSAML3 X509SubjectName DN, e.g.
 * {@code C=DK,O=11715311,CN=Hans Hansen,Serial=74c08b2b-212b-4f6d-9ce6-0fba1651087d}.
 *
 * <p>Parsed by hand rather than with {@code javax.naming.ldap.LdapName}: the
 * profile's {@code Serial} is not a registered X.500 attribute type, and an
 * LDAP parser rejects the whole DN over it.
 *
 * <p>Component lookup ignores case, and {@code Serial} also answers to
 * {@code SERIALNUMBER} so a DN issued with the registered type name still
 * resolves. {@code SN} is deliberately not an alias — in X.500 that is
 * surname, and treating it as the serial would silently key identities on the
 * person's name, which is exactly what {@code Serial} exists to avoid.
 */
public final class DistinguishedName {

    private final Map<String, String> components = new LinkedHashMap<>();

    private DistinguishedName() {}

    public static DistinguishedName parse(String dn) {
        DistinguishedName parsed = new DistinguishedName();
        if (dn == null || dn.isBlank()) {
            return parsed;
        }
        for (String part : split(dn)) {
            int equals = part.indexOf('=');
            if (equals <= 0) {
                continue;
            }
            String key = part.substring(0, equals).trim();
            String value = unescape(part.substring(equals + 1).trim());
            if (!key.isEmpty() && !value.isEmpty()) {
                // First occurrence wins: a DN with a repeated component is
                // malformed, and taking the first keeps parsing deterministic.
                parsed.components.putIfAbsent(key.toLowerCase(Locale.ROOT), value);
            }
        }
        return parsed;
    }

    /** The named component, or {@code null}. Case-insensitive. */
    public String get(String component) {
        if (component == null) {
            return null;
        }
        String key = component.trim().toLowerCase(Locale.ROOT);
        String value = components.get(key);
        if (value == null && ("serial".equals(key) || "serialnumber".equals(key))) {
            value = components.get("serial".equals(key) ? "serialnumber" : "serial");
        }
        return value;
    }

    public boolean isEmpty() {
        return components.isEmpty();
    }

    /** Splits on unescaped, unquoted commas. */
    private static List<String> split(String dn) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < dn.length(); i++) {
            char c = dn.charAt(i);
            if (c == '\\' && i + 1 < dn.length()) {
                current.append(c).append(dn.charAt(++i));
            } else if (c == '"') {
                quoted = !quoted;
            } else if (c == ',' && !quoted) {
                parts.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        parts.add(current.toString());
        return parts;
    }

    private static String unescape(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' && i + 1 < value.length()) {
                out.append(value.charAt(++i));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
