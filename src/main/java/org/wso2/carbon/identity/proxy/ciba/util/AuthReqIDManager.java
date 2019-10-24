
package org.wso2.carbon.identity.proxy.ciba.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.proxy.ciba.common.CibaParams;
import org.wso2.carbon.identity.proxy.ciba.configuration.ConfigurationFile;
import org.wso2.carbon.identity.proxy.ciba.dto.CibaAuthRequestDTO;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.UUID;


/**
 * This class create random codes for various purposes.
 */

public class AuthReqIDManager {
    private static final Log log = LogFactory.getLog(AuthReqIDManager.class);


    private AuthReqIDManager() {

    }

    private static AuthReqIDManager codeGeneratorInstance = new AuthReqIDManager();

    public static AuthReqIDManager getInstance() {
        if (codeGeneratorInstance == null) {

            synchronized (AuthReqIDManager.class) {

                if (codeGeneratorInstance == null) {

                    /* instance will be created at request time */
                    codeGeneratorInstance = new AuthReqIDManager();
                }
            }
        }
        return codeGeneratorInstance;


    }

    /**
     * This method create and returns CIBA auth_req_id
     * @param cibaAuthRequestDTO which contains the validated parameters from the cibA authentication request
     * @return JWT
     * @throws ParseException
     */
    public String getCibaAuthCode(CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException,
            JOSEException, NoSuchAlgorithmException, IdentityOAuth2Exception {


        JWTClaimsSet requestClaims = this.buildJWT(cibaAuthRequestDTO);


        Payload payload = new Payload(requestClaims.toJSONObject());

        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);


        String secret = ConfigurationFile.getInstance().getPRIVATE_KEY();
        byte[] secretKey = secret.getBytes();
        DirectEncrypter encrypter = new DirectEncrypter(secretKey);



        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(encrypter);
        String AuthReqID = jweObject.serialize();

        return AuthReqID;
    }


    /**
     * This method create and returns CIBA auth_req_id claims
     * @param cibaAuthRequestDTO which contains the validated parameters from the cibA authentication request
     * @return JWTClaimsSet
     * @throws ParseException
     */
    private JWTClaimsSet buildJWT(CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException {
        //jwt as a responseDTO

        String issuingServer = cibaAuthRequestDTO.getIssuer();
        String clientApp = cibaAuthRequestDTO.getAudience();
        String jwtIdentifier = AuthReqIDManager.getInstance().getRandomID();
        String scope = cibaAuthRequestDTO.getScope();
        String acr = cibaAuthRequestDTO.getAcrValues();
        String userCode = cibaAuthRequestDTO.getUserCode(); // can be a null string
        String bindingMessage = cibaAuthRequestDTO.getBindingMessage();// can be a null string
        String transactionContext = cibaAuthRequestDTO.getTransactionContext();// can be a null string
        String userHint = cibaAuthRequestDTO.getUserHint();
        long issuedTime = ZonedDateTime.now().toInstant().toEpochMilli();
      //  cibaAuthRequestDTO.setIssuedTime(issuedTime); //add missing values
        long durability = this.getExpiresIn(cibaAuthRequestDTO)*1000;
        long expiryTime = issuedTime+durability;
       // cibaAuthRequestDTO.setExpiredTime(expiryTime);
        long notBeforeUsable = issuedTime+ CibaParams.interval*1000;
       // cibaAuthRequestDTO.setNotBeforeTime(notBeforeUsable);

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .claim("iss", issuingServer)
                    .claim("aud", clientApp)
                    .claim("jti", jwtIdentifier)
                    .claim("exp", expiryTime)
                    .claim("iat", issuedTime)
                    .claim("nbf", notBeforeUsable)
                    .claim("scope", scope)
                    .claim("acr", acr)
                    .claim("user_code", userCode)
                    .claim("binding_message", bindingMessage)
                    .claim("transaction_context", transactionContext)
                    .claim("user_hint", userHint)
                    .build();
            return claims;


    }


    /**
     * This method create and returns CIBA auth_req_id claims
     * @return random uudi  string
     */
    public String getRandomID() {
        UUID ID = UUID.randomUUID();
        return ID.toString();

    }


    /**
     * This method create hash of the provided auth_req_id
     * @param JWTStringAsAuthReqID is a auth_req_id
     * @return String - hashed auth_req_id
     */
    public String createHash(String JWTStringAsAuthReqID) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        // getInstance() method is called with algorithm SHA-512

        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(JWTStringAsAuthReqID.getBytes());

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);

        // Convert message digest into hex value
        String hashtext = no.toString(16);

        // Add preceding 0s to make it 32 bit
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // return the HashText
        return hashtext;
    }

    /**
     * This method process and return the expiresin for auth_req_id
     * @param cibaAuthRequestDTO is a auth_req_id
     * @return long - expiry time of the auth-req_id
     */
    public long getExpiresIn(CibaAuthRequestDTO cibaAuthRequestDTO) {

        if (cibaAuthRequestDTO.getRequestedExpiry() == 0) {
           return CibaParams.expiresIn;
        } else  {
            return cibaAuthRequestDTO.getRequestedExpiry();
        }
    }




}

