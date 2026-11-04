// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.shared_helpers;

import dk.magenta.openstream.keycloak.oiosaml3.shared_helpers.PrivilegeList.Constraint;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
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
 * {@code PrivilegeGroup}, {@code Privilege} and {@code Constraint} carry no
 * namespace.
 *
 * <p>A privilege can carry data constraints (dataafgrænsninger). For a job
 * function role these are the values of its dynamic constraints: the
 * {@code Name} is the parameter URI registered for the dynamic constraint in
 * Administrationsmodulet (e.g. {@code http://kommune.dk/KLE-SEK/1/parametric}),
 * and Context Handler puts the value on the user system role that refers to
 * that parameter. They follow the {@code Privilege}, as the schema's sequence
 * requires.
 *
 * <p>A constraint value is a comma-separated list. Adding the same privilege
 * and scope again merges its constraints: values for the same name are united,
 * in first-seen order, without duplicates. A constraint with no values left
 * after trimming is dropped.
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
    /** Distinct (scope, privilege) pairs in insertion order, each with constraint name to values. */
    private final Map<Key, Map<String, Set<String>>> entries = new LinkedHashMap<>();

    private record Key(String scope, String privilege) {}

    public PrivilegeListBuilder(String namespace) {
        this.namespace = namespace;
    }

    /**
     * Adds a privilege for the authority with the given CVR. Use the user's own
     * authority, or the delegating authority's CVR for a delegated role.
     */
    public PrivilegeListBuilder add(String cvr, String privilegeUri) {
        return add(cvr, privilegeUri, List.of());
    }

    /**
     * Adds a privilege with data constraints. Each constraint's name must not
     * be blank; its value is a comma-separated list, and a constraint whose
     * list is empty is left out. Validation happens before anything is added,
     * so an exception leaves the builder unchanged.
     */
    public PrivilegeListBuilder add(String cvr, String privilegeUri, List<Constraint> constraints) {
        String trimmedCvr = cvr == null ? "" : cvr.trim();
        if (!isValidCvr(trimmedCvr)) {
            throw new IllegalArgumentException("Not an 8-digit CVR number: '" + cvr + "'");
        }
        String trimmedUri = privilegeUri == null ? "" : privilegeUri.trim();
        if (trimmedUri.isEmpty()) {
            throw new IllegalArgumentException("Privilege URI must not be empty");
        }
        for (Constraint constraint : constraints) {
            if (constraint.name() == null || constraint.name().isBlank()) {
                throw new IllegalArgumentException("Constraint name must not be empty");
            }
        }

        Map<String, Set<String>> merged = entries.computeIfAbsent(
                new Key(CVR_SCOPE_PREFIX + trimmedCvr, trimmedUri), key -> new LinkedHashMap<>());
        for (Constraint constraint : constraints) {
            List<String> values = splitValues(constraint.value());
            if (!values.isEmpty()) {
                merged.computeIfAbsent(constraint.name().trim(), name -> new LinkedHashSet<>())
                        .addAll(values);
            }
        }
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
        entries.forEach((key, constraints) -> {
            xml.append("<PrivilegeGroup Scope=\"").append(escape(key.scope())).append("\">");
            xml.append("<Privilege>").append(escape(key.privilege())).append("</Privilege>");
            constraints.forEach((name, values) -> xml.append("<Constraint Name=\"")
                    .append(escape(name))
                    .append("\">")
                    .append(escape(String.join(",", values)))
                    .append("</Constraint>"));
            xml.append("</PrivilegeGroup>");
        });
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

    /** The trimmed, non-empty items of a comma-separated constraint value. */
    public static List<String> splitValues(String value) {
        if (value == null) {
            return List.of();
        }
        return Pattern.compile(",")
                .splitAsStream(value)
                .map(String::trim)
                .filter(item -> !item.isEmpty())
                .toList();
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
