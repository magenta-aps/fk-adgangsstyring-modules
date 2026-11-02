// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.shared_helpers;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Builds an OIO Basic Privilege Profile (OIO-BPP) intermediate-model
 * {@code PrivilegeList} and base64-encodes it, ready to be used as the value of
 * the privilege attribute in an assertion sent to Context Handler.
 *
 * <p>Writes one {@code PrivilegeGroup} per privilege, as KOMBIT requires
 * ("1 PrivilegeGroup = 1 jobfunktionsrolle", Vejledning til Opsætning af
 * Identity Provider). OIO-BPP 1.2 itself allows several privileges per group,
 * but Context Handler rejects that with "Duplicate privilege has been found on
 * privilege group element". Only {@code PrivilegeList} is in the
 * bpp namespace; the schema leaves the local elements unqualified, so
 * {@code PrivilegeGroup} and {@code Privilege} carry no namespace.
 *
 * <p>Output has no whitespace between elements: values are compared as exact
 * strings by receivers, and pretty-printing would leak newlines into them.
 *
 * <p>Pure Java with no Keycloak dependency, so it can be unit tested directly.
 */
public final class PrivilegeListBuilder {

    /** OIO-BPP 1.2 namespace (OIOSAML 3). */
    public static final String NAMESPACE_DIGST = "http://digst.dk/oiosaml/basic_privilege_profile";

    /** Pre-1.2 namespace, still shown in KOMBIT's OIOSAML 2 examples. */
    public static final String NAMESPACE_ITST = "http://itst.dk/oiosaml/basic_privilege_profile";

    static final String CVR_SCOPE_PREFIX = "urn:dk:gov:saml:cvrNumberIdentifier:";

    private static final Pattern CVR = Pattern.compile("\\d{8}");

    private final String namespace;
    /** Distinct (scope, privilege) pairs, in insertion order. */
    private final Set<Entry> entries = new LinkedHashSet<>();

    private record Entry(String scope, String privilege) {}

    public PrivilegeListBuilder(String namespace) {
        this.namespace = namespace;
    }

    /**
     * Adds a privilege for the authority with the given CVR. Use the user's own
     * authority, or the delegating authority's CVR for a delegated role.
     */
    public PrivilegeListBuilder add(String cvr, String privilegeUri) {
        String trimmedCvr = cvr == null ? "" : cvr.trim();
        if (!isValidCvr(trimmedCvr)) {
            throw new IllegalArgumentException("Not an 8-digit CVR number: '" + cvr + "'");
        }
        String trimmedUri = privilegeUri == null ? "" : privilegeUri.trim();
        if (trimmedUri.isEmpty()) {
            throw new IllegalArgumentException("Privilege URI must not be empty");
        }
        entries.add(new Entry(CVR_SCOPE_PREFIX + trimmedCvr, trimmedUri));
        return this;
    }

    public boolean isEmpty() {
        return entries.isEmpty();
    }

    /** The PrivilegeList as an XML string. */
    public String toXml() {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        xml.append("<bpp:PrivilegeList xmlns:bpp=\"").append(escape(namespace)).append("\"");
        xml.append(" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">");
        for (Entry entry : entries) {
            xml.append("<PrivilegeGroup Scope=\"").append(escape(entry.scope())).append("\">");
            xml.append("<Privilege>").append(escape(entry.privilege())).append("</Privilege>");
            xml.append("</PrivilegeGroup>");
        }
        xml.append("</bpp:PrivilegeList>");
        return xml.toString();
    }

    /** The PrivilegeList, UTF-8 encoded and then base64 encoded, per OIO-BPP. */
    public String toBase64() {
        return Base64.getEncoder().encodeToString(toXml().getBytes(StandardCharsets.UTF_8));
    }

    public static boolean isValidCvr(String cvr) {
        return cvr != null && CVR.matcher(cvr).matches();
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&apos;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }
}
