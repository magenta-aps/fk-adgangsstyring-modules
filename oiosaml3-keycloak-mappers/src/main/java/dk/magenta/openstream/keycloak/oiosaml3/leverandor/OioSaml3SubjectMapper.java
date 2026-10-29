// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.leverandor;

import dk.magenta.openstream.keycloak.oiosaml3.shared_helpers.DistinguishedName;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.broker.saml.mappers.UsernameTemplateMapper;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * SAML identity-provider mapper that keys the user on the subject identifier
 * of a KOMBIT brugertoken: {@code <CVR>_<Serial>}, both taken from the
 * X509SubjectName DN in the NameID.
 *
 * <p>The profile (section 1.4.1) only promises that {@code Serial} is unique
 * <em>within the authority</em> named by {@code O}. Context Handler is one
 * identity provider for every authority, so the bare Serial is not a safe
 * key: two authorities may issue the same one, and the second person would be
 * logged in to the first person's account. Prefixing the CVR makes the key
 * unique across authorities, and it still survives a change of name, which
 * the raw NameID (CN included) does not. The separator is an underscore
 * because Keycloak's username validator rejects a colon; the CVR is always
 * exactly 8 digits, so the key splits back unambiguously.
 *
 * <p>The optional {@code professional/uuid/persistent} attribute is
 * deliberately not used. The profile does not tie it to the Serial, so
 * falling back between the two would switch the key from one login to the
 * next whenever an IdP sends both with different values.
 *
 * <p>A token without a usable DN fails the login. Both components are
 * mandatory, and the alternative, Keycloak's default of keying on the whole
 * NameID, would quietly create a second account on the next name change.
 */
public class OioSaml3SubjectMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "oiosaml3-subject-idp-mapper";

    private static final Logger LOG = Logger.getLogger(OioSaml3SubjectMapper.class);

    private static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

    private static final Set<IdentityProviderSyncMode> SUPPORTED_SYNC_MODES =
            new HashSet<>(
                    Arrays.asList(
                            IdentityProviderSyncMode.IMPORT,
                            IdentityProviderSyncMode.FORCE,
                            IdentityProviderSyncMode.LEGACY));

    private static final Pattern CVR = Pattern.compile("\\d{8}");

    static final String CONF_TARGET = "target";

    static final String TARGET_BROKER_ID = "Broker user ID";
    static final String TARGET_LOCAL = "Local username";

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
        return "Preprocessor";
    }

    @Override
    public String getDisplayType() {
        return "OIOSAML3 Subject Identifier";
    }

    @Override
    public String getHelpText() {
        return "Builds <CVR>_<Serial> from the X509SubjectName DN in the NameID and uses it as"
            + " the broker user ID or the local username. Serial is only unique within one"
            + " authority, so the CVR is part of the key. Add it before the provider's first"
            + " login: changing the broker user ID later orphans existing links.";
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return SUPPORTED_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(CONF_TARGET)
                .label("Target")
                .helpText(
                        "'Broker user ID' keys the federated identity link, which is what"
                            + " finds the returning user. 'Local username' names the Keycloak"
                            + " user. Add one mapper for each.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(TARGET_BROKER_ID, TARGET_LOCAL)
                .defaultValue(TARGET_BROKER_ID)
                .add()
                .build();
    }

    @Override
    public void preprocessFederatedIdentity(
            KeycloakSession session,
            RealmModel realm,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {

        String id = subjectId(context);
        // Set here: by the time importNewUser runs, Keycloak has already
        // looked up the federated identity and named the user.
        if (TARGET_LOCAL.equals(target(mapperModel))) {
            UsernameTemplateMapper.Target.LOCAL.set(context, id);
        } else {
            UsernameTemplateMapper.Target.BROKER_ID.set(context, id);
        }
    }

    @Override
    public void importNewUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        // preprocessFederatedIdentity already put it on the context.
    }

    @Override
    public void updateBrokeredUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {

        // The broker link is established; re-keying it mid-life is what this
        // mapper exists to avoid. Only the username follows the token.
        if (!TARGET_LOCAL.equals(target(mapperModel))) {
            return;
        }
        String id = subjectId(context);
        // Keycloak stores usernames lower-cased, so compare that way or every
        // login would look like a rename.
        if (id.equalsIgnoreCase(user.getUsername())) {
            return;
        }
        try {
            user.setUsername(id);
        } catch (ModelDuplicateException e) {
            // Another account already holds this CVR and Serial. Failing the
            // login would lock this person out of an account that is
            // otherwise fine; the conflict needs a human either way.
            LOG.warnf(
                    "Cannot rename user %s to '%s': the username is taken; leaving it as '%s'",
                    user.getId(), id, user.getUsername());
        }
    }

    /**
     * {@code <CVR>_<Serial>} from the NameID DN.
     *
     * @throws IdentityBrokerException if the NameID is not an X509SubjectName
     *     DN with an 8-digit {@code O} and a {@code Serial}
     */
    static String subjectId(BrokeredIdentityContext context) {
        String dn = SamlAssertions.subjectDn(context);
        if (dn == null) {
            throw new IdentityBrokerException(
                    "Assertion has no X509SubjectName NameID; the KOMBIT profile requires one");
        }
        DistinguishedName parsed = DistinguishedName.parse(dn);
        String cvr = parsed.get("O");
        String serial = parsed.get("Serial");
        if (cvr == null || !CVR.matcher(cvr).matches()) {
            throw new IdentityBrokerException(
                    "NameID DN has no 8-digit CVR in O: '" + dn + "'");
        }
        if (serial == null) {
            throw new IdentityBrokerException("NameID DN has no Serial: '" + dn + "'");
        }
        return cvr + "_" + serial;
    }

    private String target(IdentityProviderMapperModel mapperModel) {
        String target = Config.string(mapperModel, CONF_TARGET);
        return target == null ? TARGET_BROKER_ID : target;
    }
}
