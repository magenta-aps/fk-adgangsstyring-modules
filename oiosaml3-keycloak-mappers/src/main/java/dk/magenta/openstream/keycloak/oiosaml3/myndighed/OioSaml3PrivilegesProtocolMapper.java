// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.myndighed;

import dk.magenta.openstream.keycloak.oiosaml3.shared_helpers.PrivilegeList.Constraint;
import dk.magenta.openstream.keycloak.oiosaml3.shared_helpers.PrivilegeListBuilder;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperContainerModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.saml.mappers.AbstractSAMLProtocolMapper;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.protocol.saml.mappers.SAMLAttributeStatementMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * SAML protocol mapper for the authority (myndighed) IdP realm: emits the
 * user's job function roles (jobfunktionsroller) as an OIO-BPP
 * {@code PrivilegeList} in the assertion sent to Context Handler.
 *
 * <p>The counterpart of {@code OioSaml3PrivilegesMapper} in the
 * {@code oiosaml3-mappers} project, which reads the list Context Handler sends
 * back on the service-provider side.
 *
 * <p>Assignment works like an AD group in a municipality: a Keycloak group
 * represents a job function role, and carries the role's EntityId from
 * Fælleskommunalt Administrationsmodul in a group attribute (default
 * {@code oiosaml.jobrole}). Making a user a member of the group assigns the
 * role. A group may carry several values to emit several roles.
 *
 * <p>Scope is the authority's CVR from the mapper config. A group can override
 * it with {@code oiosaml.scope_cvr} for a role delegated by another authority.
 *
 * <p>A group can also carry values for the dynamic data constraints
 * (dataafgrænsninger) of its roles in {@code oiosaml.constraint}, as
 * {@code <parameter URI>=<value>}, keyed by the parameter URI registered for
 * the constraint in Administrationsmodulet. The attribute is multi-valued, and
 * every constraint of a group applies to every role on that group. Values are
 * comma-separated lists; the same role reached through several groups gets
 * the union of their values.
 *
 * <p>Per OIO-BPP, the attribute is omitted entirely when the user has no
 * privileges, rather than sent as an empty list.
 */
public class OioSaml3PrivilegesProtocolMapper extends AbstractSAMLProtocolMapper
        implements SAMLAttributeStatementMapper {

    public static final String PROVIDER_ID = "oiosaml3-privileges-saml-protocol-mapper";

    private static final Logger LOG = Logger.getLogger(OioSaml3PrivilegesProtocolMapper.class);

    static final String CONF_SCOPE_CVR = "scope.cvr";
    static final String CONF_NAMESPACE = "bpp.namespace";
    static final String CONF_GROUP_ATTRIBUTE = "group.jobrole.attribute";
    static final String CONF_GROUP_SCOPE_ATTRIBUTE = "group.scope.attribute";
    static final String CONF_INCLUDE_PARENTS = "include.parent.groups";
    static final String CONF_GROUP_CONSTRAINT_ATTRIBUTE = "group.constraint.attribute";

    static final String NAMESPACE_OPTION_DIGST = "OIO-BPP 1.2 (digst.dk)";
    static final String NAMESPACE_OPTION_ITST = "Legacy (itst.dk)";

    static final String DEFAULT_ATTRIBUTE_NAME =
            "https://data.gov.dk/model/core/eid/privilegesIntermediate";
    static final String DEFAULT_GROUP_ATTRIBUTE = "oiosaml.jobrole";
    static final String DEFAULT_GROUP_SCOPE_ATTRIBUTE = "oiosaml.scope_cvr";
    static final String DEFAULT_GROUP_CONSTRAINT_ATTRIBUTE = "oiosaml.constraint";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return AttributeStatementHelper.ATTRIBUTE_STATEMENT_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "OIOSAML3 Job Function Roles to PrivilegeList";
    }

    @Override
    public String getHelpText() {
        return "Builds an OIO-BPP PrivilegeList from the job function role URIs on the user's"
            + " groups, with the values of their dynamic data constraints, base64-encodes it,"
            + " and adds it as the privilegesIntermediate attribute. Omitted when the user has"
            + " no roles.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(AttributeStatementHelper.SAML_ATTRIBUTE_NAME)
                .label("SAML Attribute Name")
                .helpText(
                        "OIOSAML 3: https://data.gov.dk/model/core/eid/privilegesIntermediate."
                            + " OIOSAML 2: dk:gov:saml:attribute:Privileges_intermediate.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_ATTRIBUTE_NAME)
                .add()
                .property()
                .name(AttributeStatementHelper.SAML_ATTRIBUTE_NAMEFORMAT)
                .label("SAML Attribute NameFormat")
                .helpText("OIOSAML 3: URI Reference. OIOSAML 2: Basic.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(
                        AttributeStatementHelper.URI_REFERENCE,
                        AttributeStatementHelper.BASIC,
                        AttributeStatementHelper.UNSPECIFIED)
                .defaultValue(AttributeStatementHelper.URI_REFERENCE)
                .add()
                .property()
                .name(AttributeStatementHelper.FRIENDLY_NAME)
                .label(AttributeStatementHelper.FRIENDLY_NAME_LABEL)
                .helpText(AttributeStatementHelper.FRIENDLY_NAME_HELP_TEXT)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(CONF_NAMESPACE)
                .label("PrivilegeList Namespace")
                .helpText(
                        "XML namespace of the PrivilegeList. OIO-BPP 1.2 moved it from itst.dk"
                            + " to digst.dk; use the legacy one only if Context Handler requires"
                            + " it for this IdP's profile.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(NAMESPACE_OPTION_DIGST, NAMESPACE_OPTION_ITST)
                .defaultValue(NAMESPACE_OPTION_DIGST)
                .add()
                .property()
                .name(CONF_SCOPE_CVR)
                .label("Authority CVR")
                .helpText(
                        "8-digit CVR of the authority this IdP authenticates for. Used as the"
                            + " Scope of every role unless the group overrides it. Must match"
                            + " the O= element of the NameID and the CVR attribute.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(CONF_GROUP_ATTRIBUTE)
                .label("Group Attribute With Role URI")
                .helpText(
                        "Group attribute holding the job function role EntityId, exactly as"
                            + " shown in Administrationsmodulet. Multiple values allowed.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_GROUP_ATTRIBUTE)
                .add()
                .property()
                .name(CONF_GROUP_SCOPE_ATTRIBUTE)
                .label("Group Attribute With Delegating CVR")
                .helpText(
                        "Optional group attribute holding the CVR of a delegating authority."
                            + " When set on a group, its roles are scoped to that CVR instead.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_GROUP_SCOPE_ATTRIBUTE)
                .add()
                .property()
                .name(CONF_INCLUDE_PARENTS)
                .label("Include Parent Groups")
                .helpText(
                        "Also emit roles from the parent groups of the user's groups, matching"
                            + " how Keycloak inherits group role mappings.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property()
                .name(CONF_GROUP_CONSTRAINT_ATTRIBUTE)
                .label("Group Attribute With Constraint Value")
                .helpText(
                        "Optional group attribute holding <parameter URI>=<value> for a dynamic"
                            + " data constraint of the group's roles. The parameter URI is the one"
                            + " registered for the constraint in Administrationsmodulet. Multiple"
                            + " values allowed. Clearing it turns constraints off.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_GROUP_CONSTRAINT_ATTRIBUTE)
                .add()
                .build();
    }

    @Override
    public void validateConfig(
            KeycloakSession session,
            RealmModel realm,
            ProtocolMapperContainerModel client,
            ProtocolMapperModel mapperModel)
            throws ProtocolMapperConfigException {
        String cvr = config(mapperModel, CONF_SCOPE_CVR);
        if (!PrivilegeListBuilder.isValidCvr(cvr)) {
            // Keycloak looks the message key up in its admin message bundle and
            // throws a NullPointerException if it is null, so pass the message as
            // its own key; an unknown key falls back to the message. The message
            // also goes through MessageFormat, so it must not contain quotes or braces.
            String message = "Authority CVR must be an 8-digit CVR number";
            throw new ProtocolMapperConfigException(message, message);
        }
    }

    @Override
    public void transformAttributeStatement(
            AttributeStatementType attributeStatement,
            ProtocolMapperModel mappingModel,
            KeycloakSession session,
            UserSessionModel userSession,
            AuthenticatedClientSessionModel clientSession) {

        UserModel user = userSession.getUser();
        String defaultCvr = config(mappingModel, CONF_SCOPE_CVR);
        String roleAttribute = configOr(mappingModel, CONF_GROUP_ATTRIBUTE, DEFAULT_GROUP_ATTRIBUTE);
        String scopeAttribute = config(mappingModel, CONF_GROUP_SCOPE_ATTRIBUTE);
        boolean includeParents = !"false".equalsIgnoreCase(config(mappingModel, CONF_INCLUDE_PARENTS));
        String constraintAttribute = config(mappingModel, CONF_GROUP_CONSTRAINT_ATTRIBUTE);

        PrivilegeListBuilder builder = new PrivilegeListBuilder(namespace(mappingModel));

        for (GroupModel group : groupsOf(user, includeParents)) {
            List<String> roleUris = group.getAttributeStream(roleAttribute).toList();
            if (roleUris.isEmpty()) {
                continue;
            }
            String delegated = scopeAttribute == null ? null : group.getFirstAttribute(scopeAttribute);
            String cvr = delegated != null && !delegated.isBlank() ? delegated.trim() : defaultCvr;
            List<Constraint> constraints = constraintsOf(group, constraintAttribute);
            for (String uri : roleUris) {
                try {
                    builder.add(cvr, uri, constraints);
                } catch (IllegalArgumentException e) {
                    // One misconfigured group must not take the user's other
                    // roles with it, nor fail the whole login.
                    LOG.warnf(
                            "Skipping role '%s' on group %s for user %s: %s",
                            uri, group.getName(), user.getUsername(), e.getMessage());
                }
            }
        }

        if (builder.isEmpty()) {
            LOG.debugf("User %s has no job function roles; omitting privilege attribute",
                    user.getUsername());
            return;
        }

        LOG.debugf("PrivilegeList for user %s: %s", user.getUsername(), builder.toXml());
        AttributeStatementHelper.addAttribute(attributeStatement, mappingModel, builder.toBase64());
    }

    /**
     * The constraints a group puts on its roles, from {@code <parameter URI>=<value>}
     * entries in {@code constraintAttribute}. A malformed entry, or one without
     * a value, is logged and left out; the roles are still sent.
     */
    private static List<Constraint> constraintsOf(GroupModel group, String constraintAttribute) {
        List<Constraint> result = new ArrayList<>();
        if (constraintAttribute == null) {
            return result;
        }
        group.getAttributeStream(constraintAttribute).forEach(entry -> {
            Constraint parsed = parseEntry(entry, group, constraintAttribute);
            if (parsed == null) {
                return;
            }
            if (PrivilegeListBuilder.splitValues(parsed.value()).isEmpty()) {
                LOG.warnf(
                        "Skipping constraint '%s' on group %s: no value after '='",
                        parsed.name(), group.getName());
                return;
            }
            result.add(parsed);
        });
        return result;
    }

    /**
     * Splits {@code <parameter URI>=<value>} at the first {@code =}, trimming
     * both parts. Returns {@code null}, after logging, when there is no
     * {@code =} or the URI is blank. The value may be empty.
     */
    private static Constraint parseEntry(String entry, GroupModel group, String attribute) {
        int separator = entry == null ? -1 : entry.indexOf('=');
        String name = separator < 0 ? "" : entry.substring(0, separator).trim();
        if (name.isEmpty()) {
            LOG.warnf(
                    "Skipping '%s' in attribute %s on group %s: expected <parameter URI>=<value>",
                    entry, attribute, group.getName());
            return null;
        }
        return new Constraint(name, entry.substring(separator + 1).trim());
    }

    /** The user's groups, optionally with all their ancestors, without duplicates. */
    private static List<GroupModel> groupsOf(UserModel user, boolean includeParents) {
        Set<String> seen = new LinkedHashSet<>();
        List<GroupModel> result = new ArrayList<>();
        user.getGroupsStream().forEach(group -> {
            GroupModel current = group;
            while (current != null && seen.add(current.getId())) {
                result.add(current);
                current = includeParents ? current.getParent() : null;
            }
        });
        return result;
    }

    private static String namespace(ProtocolMapperModel model) {
        return NAMESPACE_OPTION_ITST.equals(config(model, CONF_NAMESPACE))
                ? PrivilegeListBuilder.NAMESPACE_ITST
                : PrivilegeListBuilder.NAMESPACE_DIGST;
    }

    private static String config(ProtocolMapperModel model, String key) {
        String value = model.getConfig() == null ? null : model.getConfig().get(key);
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String configOr(ProtocolMapperModel model, String key, String fallback) {
        String value = config(model, key);
        return value != null ? value : fallback;
    }
}
