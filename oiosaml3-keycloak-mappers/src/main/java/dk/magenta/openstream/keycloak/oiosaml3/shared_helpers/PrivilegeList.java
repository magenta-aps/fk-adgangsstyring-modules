// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.shared_helpers;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Parser for the {@code privilegesIntermediate} attribute: base64 wrapping an
 * OIO Basic Privilege Profile 1.2 {@code PrivilegeList}, the counterpart of
 * {@link PrivilegeListBuilder}. A value from Context Handler decodes to e.g.:
 *
 * <pre>{@code
 * <bpp:PrivilegeList xmlns:bpp="http://digst.dk/oiosaml/basic_privilege_profile">
 *   <PrivilegeGroup Scope="urn:dk:gov:saml:cvrNumberIdentifier:20374826">
 *     <Constraint Name="http://sts.kombit.dk/constraint/kle/1">25.*</Constraint>
 *     <Privilege>http://sapa.kombit.dk/roles/usersystemrole/se_sag/1</Privilege>
 *   </PrivilegeGroup>
 * </bpp:PrivilegeList>
 * }</pre>
 *
 * <p>The root must be {@code PrivilegeList} in the 1.2 namespace, or the older
 * itst.dk one that KOMBIT's own examples still use. The schema leaves
 * {@code PrivilegeGroup}, {@code Constraint} and {@code Privilege} unqualified;
 * they are matched by local name so an issuer that qualifies them anyway still
 * parses.
 *
 * <p>Free of Keycloak types so it can be unit tested without a server.
 */
public final class PrivilegeList {

    private static final Pattern CVR = Pattern.compile("\\d{8}");

    /** A data constraint (dataafgrænsning) on every privilege in its group. */
    public record Constraint(String name, String value) {}

    /**
     * One {@code PrivilegeGroup}. Its constraints apply to all of its
     * privileges together, as their intersection (KOMBIT profile 1.6).
     */
    public record PrivilegeGroup(String scope, List<Constraint> constraints, List<String> privileges) {

        /**
         * The CVR number if the Scope is a {@code cvrNumberIdentifier}, else
         * {@code null}. Other scope types (P-number, SE-number) are not CVRs
         * even when their value happens to be digits.
         */
        public String scopeCvr() {
            String prefix = PrivilegeListBuilder.CVR_SCOPE_PREFIX;
            if (scope == null || !scope.startsWith(prefix)) {
                return null;
            }
            String cvr = scope.substring(prefix.length());
            return CVR.matcher(cvr).matches() ? cvr : null;
        }
    }

    private PrivilegeList() {}

    /**
     * Decodes and parses the attribute value.
     *
     * @param base64Value the raw attribute value; whitespace is tolerated
     *     because assertion values get line-wrapped in transit
     * @return every {@code PrivilegeGroup}, in document order
     * @throws PrivilegeParseException if the value is not base64, not XML, or
     *     not a {@code PrivilegeList}
     */
    public static List<PrivilegeGroup> parse(String base64Value) {
        byte[] xml = decode(base64Value);

        Document document;
        try {
            document = newSecureDocumentBuilder().parse(new ByteArrayInputStream(xml));
        } catch (Exception e) {
            throw new PrivilegeParseException("privilege list is not parsable XML", e);
        }

        Element root = document.getDocumentElement();
        String namespace = root.getNamespaceURI();
        if (!"PrivilegeList".equals(localName(root))
                || !(PrivilegeListBuilder.NAMESPACE_DIGST.equals(namespace)
                        || PrivilegeListBuilder.NAMESPACE_ITST.equals(namespace))) {
            throw new PrivilegeParseException(
                    "root element is {" + namespace + "}" + localName(root)
                            + ", not an OIO-BPP PrivilegeList",
                    null);
        }

        List<PrivilegeGroup> groups = new ArrayList<>();
        for (Element group : children(root, "PrivilegeGroup")) {
            String scope = group.getAttribute("Scope").trim();

            List<Constraint> constraints = new ArrayList<>();
            for (Element constraint : children(group, "Constraint")) {
                constraints.add(
                        new Constraint(
                                constraint.getAttribute("Name").trim(),
                                constraint.getTextContent().trim()));
            }

            List<String> privileges = new ArrayList<>();
            for (Element privilege : children(group, "Privilege")) {
                String uri = privilege.getTextContent().trim();
                if (!uri.isEmpty()) {
                    privileges.add(uri);
                }
            }

            groups.add(
                    new PrivilegeGroup(
                            scope.isEmpty() ? null : scope,
                            List.copyOf(constraints),
                            List.copyOf(privileges)));
        }
        return groups;
    }

    private static List<Element> children(Element parent, String localName) {
        List<Element> matches = new ArrayList<>();
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child instanceof Element element && localName.equals(localName(element))) {
                matches.add(element);
            }
        }
        return matches;
    }

    private static byte[] decode(String base64Value) {
        try {
            return Base64.getDecoder().decode(base64Value.replaceAll("\\s", ""));
        } catch (IllegalArgumentException e) {
            throw new PrivilegeParseException("privilege list is not valid base64", e);
        }
    }

    private static DocumentBuilder newSecureDocumentBuilder() throws Exception {
        // The blob comes from a federated IdP, so the parser gets no DTDs, no
        // external entities and no entity expansion.
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setNamespaceAware(true);
        return factory.newDocumentBuilder();
    }

    private static String localName(Element element) {
        return element.getLocalName() != null ? element.getLocalName() : element.getTagName();
    }

    /** Thrown when the attribute value is not a decodable privilege list. */
    public static class PrivilegeParseException extends RuntimeException {
        public PrivilegeParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
