package com.example.test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.Application;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.impl.dto.ApplicationDTO;
import org.wso2.carbon.apimgt.impl.dto.JwtTokenInfoDTO;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.issuers.APIMTokenIssuer;
import org.wso2.carbon.apimgt.keymgt.util.APIMTokenIssuerUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

public class CustomAPIMTokenIssuer extends APIMTokenIssuer {

    private static final Log log = LogFactory.getLog(CustomAPIMTokenIssuer.class);

    @Override
    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        String clientId = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();

        try {
            long start_time = 0L;
            if (log.isDebugEnabled()) {
                start_time = System.nanoTime();
            }

            org.wso2.carbon.apimgt.api.model.Application application = APIUtil.getApplicationByClientId(clientId);
            if (log.isDebugEnabled()) {
                long end_time = System.nanoTime();
                long output = end_time - start_time;
                log.debug("Time taken to load the Application from database in milliseconds : " + output / 1000000L);
            }

            if (application != null) {
                String tokenType = application.getTokenType();
                if ("JWT".equals(tokenType)) {
                    OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
                    String[] audience = oAuthAppDO.getAudiences();
                    List<String> audienceList = Arrays.asList(audience);
                    String[] scopes = tokReqMsgCtx.getScope();
                    StringBuilder scopeString = new StringBuilder();
                    String[] var12 = scopes;
                    int var13 = scopes.length;

                    String accessToken;
                    for(int var14 = 0; var14 < var13; ++var14) {
                        accessToken = var12[var14];
                        scopeString.append(accessToken).append(" ");
                    }

                    ApplicationDTO applicationDTO = new ApplicationDTO();
                    applicationDTO.setId(application.getId());
                    applicationDTO.setName(application.getName());
                    applicationDTO.setTier(application.getTier());
                    applicationDTO.setOwner(application.getOwner());
                    JwtTokenInfoDTO jwtTokenInfoDTO = APIMTokenIssuerUtil.getJwtTokenInfoDTO(application, tokReqMsgCtx);
                    jwtTokenInfoDTO.setScopes(scopeString.toString().trim());
                    jwtTokenInfoDTO.setAudience(audienceList);
                    jwtTokenInfoDTO.setExpirationTime(this.getSecondsTillExpiry(tokReqMsgCtx.getValidityPeriod()));
                    jwtTokenInfoDTO.setApplication(applicationDTO);
                    jwtTokenInfoDTO.setKeyType(application.getKeyType());
                    jwtTokenInfoDTO.setConsumerKey(clientId);
                    CustomTokenGenerator apimjwtGenerator = new CustomTokenGenerator();
                    accessToken = apimjwtGenerator.generateJWT(jwtTokenInfoDTO);
                    if (log.isDebugEnabled()) {
                        long end_time_2 = System.nanoTime();
                        long output = end_time_2 - start_time;
                        log.debug("Time taken to generate the JWG in milliseconds : " + output / 1000000L);
                    }

                    return accessToken;
                }
            }
        } catch (APIManagementException var20) {
            log.error("Error occurred while getting JWT Token client ID : " + clientId, var20);
            throw new OAuthSystemException("Error occurred while getting JWT Token client ID : " + clientId, var20);
        } catch (InvalidOAuthClientException var21) {
            log.error("Error occurred while getting JWT Token client ID : " + clientId + " when getting oAuth App " + "information", var21);
            throw new OAuthSystemException("Error occurred while getting JWT Token client ID : " + clientId, var21);
        } catch (IdentityOAuth2Exception var22) {
            log.error("Error occurred while getting JWT Token client ID : " + clientId + " when getting oAuth App " + "information", var22);
            throw new OAuthSystemException("Error occurred while getting JWT Token client ID : " + clientId, var22);
        }

        return super.accessToken(tokReqMsgCtx);
    }

    private long getSecondsTillExpiry(long validityPeriod) throws APIManagementException {
        if (validityPeriod == -1L) {
            KeyManagerConfiguration configuration = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
            return Long.parseLong(configuration.getParameter("VALIDITY_PERIOD"));
        } else {
            return validityPeriod == -2L ? 2147483647L : validityPeriod;
        }
    }

    public String getAccessTokenHash(String accessToken) throws OAuthSystemException {
        if (StringUtils.isNotEmpty(accessToken) && accessToken.contains(".")) {
            try {
                JWT parse = JWTParser.parse(accessToken);
                return parse.getJWTClaimsSet().getJWTID();
            } catch (ParseException var3) {
                if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable("AccessToken")) {
                    log.debug("Error while getting JWTID from token: " + accessToken);
                }

                throw new OAuthSystemException("Error while getting access token hash", var3);
            }
        } else {
            return accessToken;
        }
    }

    public boolean renewAccessTokenPerRequest(OAuthTokenReqMessageContext tokReqMsgCtx) {
        String clientId = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();

        try {
            Application application = APIUtil.getApplicationByClientId(clientId);
            if (null != application && "JWT".equals(application.getTokenType())) {
                return true;
            }
        } catch (APIManagementException var5) {
            log.error("Error occurred while getting Token type.", var5);
        }

        return false;
    }

}
