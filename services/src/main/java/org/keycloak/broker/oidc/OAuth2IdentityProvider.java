package org.keycloak.broker.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;


/**
 * 通用OAuth2 Identity Provider，实现标准OAuth2授权码流程，支持动态配置。
 */
public class OAuth2IdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig> {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final Logger logger = Logger.getLogger(OAuth2IdentityProvider.class);

    public OAuth2IdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new OAuth2IdentityProvider.Oauth2Endpoint(callback, realm, event);
    }

    protected class Oauth2Endpoint extends Endpoint {
        public Oauth2Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            super(callback, realm, event);
        }
    }

    @Override
    public Response keycloakInitiatedBrowserLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        logger.debug("前端浏览器向IDP发送注销请求");
        String logoutUrl = getConfig().getConfig().get("logoutUrl");
        if (logoutUrl == null || logoutUrl.trim().equals("")) return null;
        String sessionId = userSession.getId();
        UriBuilder logoutUri = UriBuilder.fromUri(logoutUrl)
                .queryParam("state", sessionId);
        return Response.status(302).location(logoutUri.build()).build();
    }

    @Override
    public void backchannelLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        logger.debug("后端向IDP发送注销请求");
        String logoutUrl = getConfig().getConfig().get("logoutUrl");
        if (logoutUrl == null || logoutUrl.trim().equals("")) return;
        String sessionId = userSession.getId();
        UriBuilder logoutUri = UriBuilder.fromUri(logoutUrl)
                .queryParam("state", sessionId);
        String url = logoutUri.build().toString();
        try {
            SimpleHttp.doGet(url, session).asResponse().close();
        } catch (IOException e) {
            logger.warn("Failed backchannel broker logout to: " + url);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return "";
    }

    private String verifyAccessToken(AccessTokenResponse tokenResponse) {
        String accessToken = tokenResponse.getToken();

        if (accessToken == null) {
            throw new IdentityBrokerException("No access_token from server.");
        }
        return accessToken;
    }

    /**
     * {
     * 	"access_token":"skiew234i3i4o6uy77b4k3b3v2j1vv53j",
     * 	"expires_in":"1500",
     *  	"refresh_token":"iewoer233422i34o2i34uio55iojhg6g",
     *  	"uid":"20201203220026862-0165-5B12D4358"
     * }
     * @param response
     * @return
     */
    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        logger.debug("getFederatedIdentity:" + response);
        AccessTokenResponse tokenResponse;
        try {
            tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
        } catch (IOException e) {
            throw new IdentityBrokerException("Could not decode access token response.", e);
        }
        String accessToken = verifyAccessToken(tokenResponse);
        try {
            BrokeredIdentityContext identity = getUserInfo(accessToken);
            identity.setToken(accessToken);
            return identity;
        } catch (IOException e) {
            logger.error("Failed to parse token or user info response", e);
            throw new IdentityBrokerException("Failed to parse token or user info response", e);
        }
    }

    private BrokeredIdentityContext getUserInfo(String accessToken) throws IOException {
        logger.info("getUserInfo");
        SimpleHttp getUserInfo = SimpleHttp.doGet(getConfig().getUserInfoUrl(), session)
                .param(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
                .param(OAUTH2_PARAMETER_ACCESS_TOKEN, accessToken);
        SimpleHttp.Response response = getUserInfo.asResponse();
        String responseStr = response.asString();
        logger.debug(responseStr);
        JsonNode newTokenJson = mapper.readTree(responseStr);
        if (null != newTokenJson.get("errcode")) {
            throw new IdentityBrokerException("Failed to get user info from " + getConfig().getUserInfoUrl() + ": " + newTokenJson.get("errcode").asText());
        }
        BrokeredIdentityContext identity = new BrokeredIdentityContext(newTokenJson.get("loginName").asText());
        identity.setUsername(newTokenJson.get("loginName").asText());
        identity.setId(newTokenJson.get("loginName").asText());
        identity.setFirstName(newTokenJson.get("loginName").asText());
        return identity;
    }
}