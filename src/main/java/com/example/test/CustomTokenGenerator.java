package com.example.test;


import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.dto.JwtTokenInfoDTO;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.token.APIMJWTGenerator;
import org.wso2.carbon.apimgt.keymgt.token.JWTGenerator;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;


public class CustomTokenGenerator extends JWTGenerator {

    private static final Log log = LogFactory.getLog(APIMJWTGenerator.class);
    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    private String signatureAlgorithm = "SHA256withRSA";
    private static final String NONE = "NONE";
    private String userAttributeSeparator = ",";
    private static ConcurrentHashMap<Integer, Certificate> publicCerts = new ConcurrentHashMap<Integer, Certificate>();


    public String generateJWT(JwtTokenInfoDTO jwtTokenInfoDTO) throws APIManagementException {
        String jwtHeader = this.buildHeader(jwtTokenInfoDTO);
        String base64UrlEncodedHeader = "";
        if (jwtHeader != null) {
            base64UrlEncodedHeader = java.util.Base64.getUrlEncoder().encodeToString(jwtHeader.getBytes(Charset.defaultCharset()));
        }

        String jwtBody = this.buildBody(jwtTokenInfoDTO);
        String base64UrlEncodedBody = "";
        if (jwtBody != null) {
            base64UrlEncodedBody = java.util.Base64.getUrlEncoder().encodeToString(jwtBody.getBytes());
        }

        if ("SHA256withRSA".equals(this.signatureAlgorithm)) {
            String assertion = base64UrlEncodedHeader + '.' + base64UrlEncodedBody;
            byte[] signedAssertion = this.signJWT(assertion, jwtTokenInfoDTO.getEndUserName());
            if (log.isDebugEnabled()) {
                log.debug("signed assertion value : " + new String(signedAssertion, Charset.defaultCharset()));
            }

            String base64UrlEncodedAssertion = java.util.Base64.getUrlEncoder().encodeToString(signedAssertion);
            return base64UrlEncodedHeader + '.' + base64UrlEncodedBody + '.' + base64UrlEncodedAssertion;
        } else {
            return base64UrlEncodedHeader + '.' + base64UrlEncodedBody + '.';
        }
    }

    public String buildHeader(JwtTokenInfoDTO JwtTokenInfoDTO) throws APIManagementException {
        String jwtHeader = null;
        if ("NONE".equals(this.signatureAlgorithm)) {
            StringBuilder jwtHeaderBuilder = new StringBuilder();
            jwtHeaderBuilder.append("{\"typ\":\"JWT\",");
            jwtHeaderBuilder.append("\"alg\":\"");
            jwtHeaderBuilder.append(this.getJWSCompliantAlgorithmCode("NONE"));
            jwtHeaderBuilder.append('"');
            jwtHeaderBuilder.append("\"kid\":\"\"");
            jwtHeaderBuilder.append('}');
            jwtHeader = jwtHeaderBuilder.toString();
        } else if ("SHA256withRSA".equals(this.signatureAlgorithm)) {
            jwtHeader = this.addCertToHeader(JwtTokenInfoDTO.getEndUserName());
        }

        return jwtHeader;
    }

    public String buildBody(JwtTokenInfoDTO jwtTokenInfoDTO) throws APIManagementException {
        Map<String, Object> standardClaims = this.populateStandardClaims(jwtTokenInfoDTO);
        int tenantId = APIUtil.getTenantId(jwtTokenInfoDTO.getEndUserName());
        String claimSeparator = this.getMultiAttributeSeparator(tenantId);
        if (StringUtils.isNotBlank(claimSeparator)) {
            this.userAttributeSeparator = claimSeparator;
        }

        if (standardClaims == null) {
            return null;
        } else {
            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
            Iterator it = (new TreeSet(standardClaims.keySet())).iterator();

            while(true) {
                while(true) {
                    while(it.hasNext()) {
                        String claimURI = (String)it.next();
                        Object claimValObj = standardClaims.get(claimURI);
                        if (claimValObj instanceof String) {
                            String claimVal = (String)claimValObj;
                            List<String> claimList = new ArrayList();
                            if (this.userAttributeSeparator != null && claimVal.contains(this.userAttributeSeparator)) {
                                StringTokenizer st = new StringTokenizer(claimVal, this.userAttributeSeparator);

                                while(st.hasMoreElements()) {
                                    String attValue = st.nextElement().toString();
                                    if (StringUtils.isNotBlank(attValue)) {
                                        claimList.add(attValue);
                                    }
                                }

                                jwtClaimsSetBuilder.claim(claimURI, claimList.toArray(new String[claimList.size()]));
                            } else if ("exp".equals(claimURI)) {
                                jwtClaimsSetBuilder.claim("exp", new Date(Long.valueOf((String)standardClaims.get(claimURI))));
                            } else {
                                jwtClaimsSetBuilder.claim(claimURI, claimVal);
                            }
                        } else if (claimValObj != null) {
                            jwtClaimsSetBuilder.claim(claimURI, claimValObj);
                        }
                    }

                    return jwtClaimsSetBuilder.build().toJSONObject().toJSONString();
                }
            }
        }
    }

    public Map<String, Object> populateStandardClaims(JwtTokenInfoDTO jwtTokenInfoDTO) throws APIManagementException {
        long currentTime = System.currentTimeMillis();
        long expireIn = TimeUnit.MILLISECONDS.toSeconds(currentTime) + jwtTokenInfoDTO.getExpirationTime();
        String endUserName = jwtTokenInfoDTO.getEndUserName();
        Map<String, Object> claims = new LinkedHashMap(20);
        String issuerIdentifier = OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenIssuerIdentifier();
        claims.put("sub", endUserName);
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iss", issuerIdentifier);
        claims.put("aud", jwtTokenInfoDTO.getAudience());
        claims.put("iat", currentTime);
        claims.put("exp", expireIn);
        claims.put("scope", jwtTokenInfoDTO.getScopes());
        claims.put("subscribedAPIs", jwtTokenInfoDTO.getSubscribedApiDTOList());
        claims.put("application", jwtTokenInfoDTO.getApplication());
        claims.put("keytype", jwtTokenInfoDTO.getKeyType());
        claims.put("consumerKey", jwtTokenInfoDTO.getConsumerKey());
        return claims;
    }

    /**
     * Helper method to add public certificate to JWT_HEADER to signature verification.
     *
     * @param endUserName - The end user name
     * @throws APIManagementException
     */
    protected String addCertToHeader(String endUserName) throws APIManagementException {

        try {
            //get tenant domain
            String tenantDomain = MultitenantUtils.getTenantDomain(endUserName);
            //get tenantId
            int tenantId = APIUtil.getTenantId(endUserName);
            Certificate publicCert;

            if (!(publicCerts.containsKey(tenantId))) {
                //get tenant's key store manager
                APIUtil.loadTenantRegistry(tenantId);
                KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

                KeyStore keyStore;
                if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                    //derive key store name
                    String ksName = tenantDomain.trim().replace('.', '-');
                    String jksName = ksName + ".jks";
                    keyStore = tenantKSM.getKeyStore(jksName);
                    publicCert = keyStore.getCertificate(tenantDomain);
                } else {
                    //keyStore = tenantKSM.getPrimaryKeyStore();
                    publicCert = tenantKSM.getDefaultPrimaryCertificate();
                }
                if (publicCert != null) {
                    publicCerts.put(tenantId, publicCert);
                }
            } else {
                publicCert = publicCerts.get(tenantId);
            }

            //generate the SHA-1 thumbprint of the certificate
            //TODO: maintain a hashmap with tenants' pubkey thumbprints after first initialization
            MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
            if (publicCert != null) {
                byte[] der = publicCert.getEncoded();
                digestValue.update(der);
                byte[] digestInBytes = digestValue.digest();
                String publicCertThumbprint = hexify(digestInBytes);
                Base64 base64 = new Base64(true);
                String base64UrlEncodedThumbPrint = base64.encodeToString(
                        publicCertThumbprint.getBytes(Charsets.UTF_8)).trim();
                StringBuilder jwtHeader = new StringBuilder();
                //Sample header
                //{"typ":"JWT", "alg":"SHA256withRSA", "x5t":"a_jhNus21KVuoFx65LmkW2O_l10"}
                //{"typ":"JWT", "alg":"[2]", "x5t":"[1]"}
                jwtHeader.append("{\"typ\":\"JWT\",");
                jwtHeader.append("\"alg\":\"");
                jwtHeader.append(getJWSCompliantAlgorithmCode(signatureAlgorithm));
                jwtHeader.append("\",");

                jwtHeader.append("\"x5t\":\"");
                jwtHeader.append(base64UrlEncodedThumbPrint);
                jwtHeader.append("\",");
                jwtHeader.append("\"kid\":\"\"");
                jwtHeader.append('}');
                return jwtHeader.toString();
            } else {
                String error = "Error in obtaining tenant's keystore";
                throw new APIManagementException(error);
            }

        } catch (KeyStoreException e) {
            String error = "Error in obtaining tenant's keystore";
            throw new APIManagementException(error, e);
        } catch (CertificateEncodingException e) {
            String error = "Error in generating public cert thumbprint";
            throw new APIManagementException(error, e);
        } catch (NoSuchAlgorithmException e) {
            String error = "Error in generating public cert thumbprint";
            throw new APIManagementException(error, e);
        } catch (Exception e) {
            String error = "Error in obtaining tenant's keystore";
            throw new APIManagementException(error, e);
        }
    }

    /**
     * Helper method to hexify a byte array.
     * TODO:need to verify the logic
     *
     * @param bytes - The input byte array
     * @return hexadecimal representation
     */
    private String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        for (byte aByte : bytes) {
            buf.append(hexDigits[(aByte & 0xf0) >> 4]);
            buf.append(hexDigits[aByte & 0x0f]);
        }
        return buf.toString();
    }
}
