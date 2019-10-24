package org.wso2.carbon.identity.proxy.ciba.util;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.proxy.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.proxy.ciba.common.CibaParams;
import org.wso2.carbon.identity.proxy.ciba.configuration.ConfigurationFile;
import org.wso2.carbon.identity.proxy.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.proxy.ciba.model.CibaAuthCodeDO;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;


public class CibaAuthCodeDOBuilder {


    private static final Log log = LogFactory.getLog(CibaAuthCodeDOBuilder.class);
    private CibaAuthCodeDOBuilder() {

    }

    private static CibaAuthCodeDOBuilder CibaAuthCodeDOBuilderInstance = new CibaAuthCodeDOBuilder();

    public static CibaAuthCodeDOBuilder getInstance() {
        if (CibaAuthCodeDOBuilderInstance == null) {

            synchronized (CibaAuthCodeDOBuilder.class) {

                if (CibaAuthCodeDOBuilderInstance == null) {

                    /* instance will be created at request time */
                    CibaAuthCodeDOBuilderInstance = new CibaAuthCodeDOBuilder();
                }
            }
        }
        return CibaAuthCodeDOBuilderInstance;


    }

    public CibaAuthCodeDO buildCibaAuthCodeDO(String cibaAuthCode, CibaAuthRequestDTO cibaAuthRequestDTO) throws NoSuchAlgorithmException, ParseException {


/*
        SignedJWT signedJWT = SignedJWT.parse(cibaAuthCode);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();*/

      /*  String  lastpolledTimeasString = jo.get("iat").toString();
        long lastPolledTime = Long.parseLong(lastpolledTimeasString);
        log.info("last polled here"+lastPolledTime);
        String  expiryTimeasString = jo.get("exp").toString();
        long expiryTime = Long.parseLong(expiryTimeasString);
        log.info("expiry herre"+ expiryTime);*/


      long lastPolledTime = cibaAuthRequestDTO.getIssuedTime();
      long expiryTime = cibaAuthRequestDTO.getExpiredTime();

        String bindingMessage;
        String transactionContext;
        String scope;


        if (cibaAuthRequestDTO.getBindingMessage() == null || cibaAuthRequestDTO.getBindingMessage().equals("null")){
            bindingMessage= "null";

        } else{
            bindingMessage = cibaAuthRequestDTO.getBindingMessage() ;
            log.info("binding herre" + bindingMessage);
        }



        if (cibaAuthRequestDTO.getTransactionContext() == null || cibaAuthRequestDTO.getTransactionContext().equals("null")){
            transactionContext= "null";

        } else{
            transactionContext  = cibaAuthRequestDTO.getTransactionContext();
            log.info("transaction value herre" + transactionContext);
        }


        if (cibaAuthRequestDTO.getScope() == null ||
               cibaAuthRequestDTO.getScope().equals("null")){
            scope= "null";

        } else{
            scope  =  cibaAuthRequestDTO.getScope();
            log.info("scope" + scope);
        }



        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        cibaAuthCodeDO.setCibaAuthCodeID(AuthReqIDManager.getInstance().getRandomID());
        cibaAuthCodeDO.setCibaAuthCode(cibaAuthCode);
        cibaAuthCodeDO.setHashedCibaAuthCode(AuthReqIDManager.getInstance().createHash(cibaAuthCode));
        cibaAuthCodeDO.setAuthenticationStatus(AuthenticationStatus.REQUESTED.toString());
        cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
        cibaAuthCodeDO.setInterval(CibaParams.interval);
        cibaAuthCodeDO.setExpiryTime(expiryTime);
        cibaAuthCodeDO.setBindingMessage(bindingMessage);
        cibaAuthCodeDO.setTransactionContext(transactionContext);
        cibaAuthCodeDO.setScope(scope);


            return cibaAuthCodeDO;
    }


}
