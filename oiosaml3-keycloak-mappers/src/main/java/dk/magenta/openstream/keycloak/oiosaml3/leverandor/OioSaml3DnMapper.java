// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.leverandor;

import dk.magenta.openstream.keycloak.oiosaml3.shared_helpers.DistinguishedName;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * SAML identity-provider mapper that copies one component of the
 * X509SubjectName DN in the NameID ({@code C}, {@code O}, {@code CN} or
 * {@code Serial}) to the user's first name, last name or a user attribute.
 *
 * <p>These four are all the profile puts in the DN, and all of them are
 * mandatory. Keying the user is not this mapper's job:
 * {@link OioSaml3SubjectMapper} owns the username and the broker link, because
 * {@code Serial} on its own is only unique within one authority.
 */
public class OioSaml3DnMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "oiosaml3-dn-idp-mapper";

    private static final Logger LOG = Logger.getLogger(OioSaml3DnMapper.class);

    private static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

    private static final Set<IdentityProviderSyncMode> SUPPORTED_SYNC_MODES =
            new HashSet<>(
                    Arrays.asList(
                            IdentityProviderSyncMode.IMPORT,
                            IdentityProviderSyncMode.FORCE,
                            IdentityProviderSyncMode.LEGACY));

    static final String CONF_COMPONENT = "dn.component";
    static final String CONF_TARGET = "target";
    static final String CONF_USER_ATTRIBUTE = "user.attribute";
    static final String CONF_TRANSFORM = "value.transform";

    static final String TARGET_FIRST_NAME = "First name";
    static final String TARGET_LAST_NAME = "Last name";
    static final String TARGET_USER_ATTRIBUTE = "User attribute";

    static final String TRANSFORM_NONE = "None";
    static final String TRANSFORM_FIRST_WORD = "First word";
    static final String TRANSFORM_REST = "All but first word";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Attribute Importer";
    }

    @Override
    public String getDisplayType() {
        return "OIOSAML3 DN Component";
    }

    @Override
    public String getHelpText() {
        return "Copies one component of the X509SubjectName DN in the NameID (C, O, CN or"
            + " Serial) to the first name, last name or a user attribute. Use the OIOSAML3"
            + " Subject Identifier mapper for the username and the broker link.";
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return SUPPORTED_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(CONF_COMPONENT)
                .label("DN Component")
                .helpText(
                        "C is the country code, O the authority's CVR, CN the person's name"
                            + " and Serial their ID within the authority.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options("CN", "O", "C", "Serial")
                .defaultValue("CN")
                .add()
                .property()
                .name(CONF_TARGET)
                .label("Target")
                .helpText("Where the value goes.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(TARGET_FIRST_NAME, TARGET_LAST_NAME, TARGET_USER_ATTRIBUTE)
                .defaultValue(TARGET_USER_ATTRIBUTE)
                .add()
                .property()
                .name(CONF_USER_ATTRIBUTE)
                .label("User Attribute")
                .helpText("Attribute name to write when the target is 'User attribute'.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(CONF_TRANSFORM)
                .label("Transform")
                .helpText(
                        "Applied before writing. 'First word' / 'All but first word' split a CN"
                            + " like 'Hans Hansen' into given and family name.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(TRANSFORM_NONE, TRANSFORM_FIRST_WORD, TRANSFORM_REST)
                .defaultValue(TRANSFORM_NONE)
                .add()
                .build();
    }

    @Override
    public void preprocessFederatedIdentity(
            KeycloakSession session,
            RealmModel realm,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {

        // Keycloak copies these onto the user it creates at first login.
        String value = value(mapperModel, context);
        if (value == null) {
            return;
        }
        switch (target(mapperModel)) {
            case TARGET_FIRST_NAME -> context.setFirstName(value);
            case TARGET_LAST_NAME -> context.setLastName(value);
            default -> {
                String attribute = Config.string(mapperModel, CONF_USER_ATTRIBUTE);
                if (attribute != null) {
                    context.setUserAttribute(attribute, value);
                }
            }
        }
    }

    @Override
    public void importNewUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        // preprocessFederatedIdentity already put the value on the context.
    }

    @Override
    public void updateBrokeredUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {

        String value = value(mapperModel, context);
        if (value == null) {
            return;
        }
        switch (target(mapperModel)) {
            case TARGET_FIRST_NAME -> user.setFirstName(value);
            case TARGET_LAST_NAME -> user.setLastName(value);
            default -> {
                String attribute = Config.string(mapperModel, CONF_USER_ATTRIBUTE);
                if (attribute != null) {
                    user.setSingleAttribute(attribute, value);
                }
            }
        }
    }

    /** The configured DN component, transformed, or {@code null} if absent. */
    static String value(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String dn = SamlAssertions.subjectDn(context);
        if (dn == null) {
            LOG.warn("Assertion has no X509SubjectName NameID");
            return null;
        }
        String component = Config.string(mapperModel, CONF_COMPONENT);
        if (component == null) {
            component = "CN";
        }
        String value = DistinguishedName.parse(dn).get(component);
        if (value == null) {
            LOG.warnf("NameID DN has no '%s' component", component);
            return null;
        }
        return transform(value, Config.string(mapperModel, CONF_TRANSFORM));
    }

    private static String target(IdentityProviderMapperModel mapperModel) {
        String target = Config.string(mapperModel, CONF_TARGET);
        return target == null ? TARGET_USER_ATTRIBUTE : target;
    }

    static String transform(String value, String transform) {
        if (transform == null) {
            return value;
        }
        return switch (transform) {
            case TRANSFORM_FIRST_WORD -> value.split("\\s+")[0];
            case TRANSFORM_REST -> {
                int firstSpace = value.indexOf(' ');
                // A single-word CN has no family name to give: keep the whole
                // value rather than writing an empty last name.
                yield firstSpace < 0 ? value : value.substring(firstSpace + 1).trim();
            }
            default -> value;
        };
    }
}
