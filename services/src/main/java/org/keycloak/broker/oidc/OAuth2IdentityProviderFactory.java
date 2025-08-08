package org.keycloak.broker.oidc;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.IdentityProviderModel;

/**
 * 通用OAuth2 Identity Provider工厂类，支持Keycloak后台动态配置。
 */
public class OAuth2IdentityProviderFactory extends AbstractIdentityProviderFactory<OAuth2IdentityProvider> {
    public static final String PROVIDER_ID = "oauth2";

    @Override
    public String getName() {
        return "OAuth2";
    }

    @Override
    public OAuth2IdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new OAuth2IdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public OAuth2IdentityProviderConfig createConfig() {
        return new OAuth2IdentityProviderConfig();
    }
}