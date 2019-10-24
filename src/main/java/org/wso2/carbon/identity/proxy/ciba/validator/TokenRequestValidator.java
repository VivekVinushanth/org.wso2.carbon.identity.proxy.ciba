package org.wso2.carbon.identity.proxy.ciba.validator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.proxy.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.proxy.ciba.common.CibaParams;
import org.wso2.carbon.identity.proxy.ciba.configuration.ConfigurationFile;
import org.wso2.carbon.identity.proxy.ciba.dao.CibaAuthResponseMgtDAO;
import org.wso2.carbon.identity.proxy.ciba.dto.CibaResponseContextDTO;
import org.wso2.carbon.identity.proxy.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.proxy.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.proxy.ciba.util.AuthReqIDManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import java.time.ZonedDateTime;
import java.util.Map;

public class TokenRequestValidator {


    private static final Log log = LogFactory.getLog(TokenRequestValidator.class);

    private TokenRequestValidator() {

    }

    private static TokenRequestValidator TokenRequestValidatorInstance = new TokenRequestValidator();

    public static TokenRequestValidator getInstance() {
        if (TokenRequestValidatorInstance == null) {

            synchronized (TokenRequestValidator.class) {

                if (TokenRequestValidatorInstance == null) {

                    /* instance will be created at request time */
                    TokenRequestValidatorInstance = new TokenRequestValidator();
                }
            }
        }
        return TokenRequestValidatorInstance;

    }


    public boolean isValidTokenRequest(@Context HttpServletRequest request, CibaResponseContextDTO cibaResponseContextDTO,CibaAuthCodeDO cibaAuthCodeDO) throws Exception {

        Map<String, String[]> attributeNames = request.getParameterMap();

        if(!attributeNames.containsKey(CibaParams.AUTH_REQ_ID) || !attributeNames.containsKey(CibaParams.RESPONSE_TYPE)) {
            String authReqID = attributeNames.get(CibaParams.AUTH_REQ_ID).toString();
            String grant = attributeNames.get(CibaParams.RESPONSE_TYPE).toString();

            String authCodeID = this.getCodeIDfromAuthReqCodeHash(authReqID);

            CibaAuthResponseMgtDAO.getInstance().getAuthCodeDO(authCodeID, cibaAuthCodeDO);

            if (IsValidGrant(grant).equals(false)) {
                cibaResponseContextDTO.setErrorCode(HttpServletResponse.SC_UNAUTHORIZED);
                cibaResponseContextDTO.setError(ErrorCodes.INVALID_GRANTTYPE);
                cibaResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.IMPROPER_GRANTTYPE);
                return false;

            } else if(IsAuthReqIDValid(authCodeID).equals(false)) {
                cibaResponseContextDTO.setErrorCode(HttpServletResponse.SC_UNAUTHORIZED);
                cibaResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                cibaResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_AUTHREQID);
                return false;

        }else if (IsPollingAllowed(cibaAuthCodeDO).equals(false)) {
               cibaResponseContextDTO.setErrorCode(HttpServletResponse.SC_BAD_REQUEST);
               cibaResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_TOKEN_REQUEST_MODE);
               cibaResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNAUTHORIZED_MODE);
               return false;

            } else if (IsAuthReqIDActive(cibaAuthCodeDO).equals(false)) {
               cibaResponseContextDTO.setErrorCode(HttpServletResponse.SC_BAD_REQUEST);
               cibaResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
               cibaResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.EXPIRED_AUTH_REQ_ID);
               return false;

            } else if (IsCorrectPollingFrequency(cibaAuthCodeDO).equals(false)) {
               cibaResponseContextDTO.setErrorCode(HttpServletResponse.SC_BAD_REQUEST);
               cibaResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
               cibaResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.SLOWDOWN);
               return false;

            } else if (IsConsentGiven(cibaAuthCodeDO).equals(false)) {
               cibaResponseContextDTO.setErrorCode(HttpServletResponse.SC_BAD_REQUEST);
               cibaResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
               cibaResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.ACCESS_DENIED);
               return false;

            } else if (IsUserAuthenticated(cibaAuthCodeDO).equals(false)) {
               cibaResponseContextDTO.setErrorCode(HttpServletResponse.SC_BAD_REQUEST);
               cibaResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
               cibaResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.PENDING);
               return false;

            } else {

                return true;
            }
        } else {
            cibaResponseContextDTO.setErrorCode(HttpServletResponse.SC_BAD_REQUEST);
            cibaResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            cibaResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            return false;
        }

    }

    private Boolean IsValidGrant(String grant) {
        if(grant.equals(ConfigurationFile.getInstance().getGRANT_TYPE())) {
            return true;
        } else {
            return false;
        }
    }


    public Boolean IsConsentGiven(CibaAuthCodeDO cibaAuthCodeDO) {
            if(cibaAuthCodeDO.getAuthenticationStatus().equals(AuthenticationStatus.DENIED.toString())){
                return false;
            } else {
                return true;
            }
        }


        public String getCodeIDfromAuthReqCodeHash(String authReqID)
                throws Exception {
            /*  String authReqID = auth_req_id.toString();*/
            String hashedCibaAuthReqCode = AuthReqIDManager.getInstance().createHash(authReqID);


            if (CibaAuthResponseMgtDAO.getInstance().isHashedAuthIDExists(hashedCibaAuthReqCode)) {
                return CibaAuthResponseMgtDAO.getInstance().getCibaAuthReqCodeID(hashedCibaAuthReqCode);
            }else {
                return null;
            }

        }

        public Boolean IsAuthReqIDValid(String authReqID) throws Exception {
            //to check whether auth_req_id issued or not
            boolean isValid;
            /*String authReqID = authReqID;*/
            String hashedAuthReqID = AuthReqIDManager.getInstance().createHash(authReqID);


            //check whether the incoming auth_req_id exists/ valid.
            if(CibaAuthResponseMgtDAO.getInstance().isHashedAuthIDExists(hashedAuthReqID)){
             /*   isValid = this.isValidAudience(auth_req_id);
                //check whether the audience is valid [audiene has to be clienID]


                isValid = this.isValidIssuer(auth_req_id);*/
                //check whether the issuer of authReqID is WSO2-IS-CIBA

                return true;
            }else{
                isValid=false;
                return  isValid;
            }


        }


        public Boolean IsAuthReqIDActive(CibaAuthCodeDO cibaAuthCodeDO){
            //to check whether auth_req_id has expired or not
            /*        String expiryTimeasString = String.valueOf(auth_req_id.get("exp"));*/
            long expiryTime = cibaAuthCodeDO.getExpiryTime();

            long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
            if (currentTime >  expiryTime) {
                if(log.isDebugEnabled()){
                    log.debug("CIBA AuthReqID is in expired state.Token Request Denied.");
                }
                return false;

            } else {
                if(log.isDebugEnabled()){
                    log.debug("CIBA AuthReqID is in active state.Token request accepted.");
                }

                return true;
            }
        }

        public Boolean IsPollingAllowed(CibaAuthCodeDO cibaAuthCodeDO) {
            return  true;  //incase if implementing 'ping mode' in future.
        }


        public Boolean IsCorrectPollingFrequency(CibaAuthCodeDO cibaAuthCodeDO)
                throws Exception {
            //Check the frequency of polling and do the needfull
            //String cibaAuthCodeID = this.getCodeIDfromAuthReqCodeHash(auth_req_id);
            long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();

            long lastpolltime = cibaAuthCodeDO.getLastPolledTime();
            long interval = cibaAuthCodeDO.getInterval();
            String cibaAuthCodeID = cibaAuthCodeDO.getCibaAuthCodeID();

            if(currentTime - lastpolltime > interval*1000){

                CibaAuthResponseMgtDAO.getInstance().updateLastPollingTime(cibaAuthCodeID,currentTime);

                return true;
            }else {
                long newInterval = interval+CibaParams.INTERVAL_INCREMENT;
                if(log.isDebugEnabled()){
                    log.debug("Incorrect Polling frequency.Updated the Polling frequency on the table.");
                }

                CibaAuthResponseMgtDAO.getInstance().updatePollingInterval(cibaAuthCodeID,newInterval);
                return false;
            }
        }

        public Boolean IsUserAuthenticated(CibaAuthCodeDO cibaAuthCodeDO)
                throws Exception {

            //String cibaAuthCodeID = this.getCodeIDfromAuthReqCodeHash(authReqID);

            // String authenticationStatus = CibaAuthResponseMgtDAO.getInstance().getAuthenticationStatus(cibaAuthCodeID);

            String authenticationStatus = cibaAuthCodeDO.getAuthenticationStatus();
            String cibaAuthCodeID = cibaAuthCodeDO.getCibaAuthCodeID();
            if(authenticationStatus.equals(AuthenticationStatus.AUTHENTICATED.toString())){
                //if authenticated update the status as token delivered.
                CibaAuthResponseMgtDAO.getInstance().persistStatus(cibaAuthCodeID,AuthenticationStatus.
                        TOKEN_DELIEVERED.toString());
                log.info("User Authenticated.");
                return  true;
            } else if (authenticationStatus.equals(AuthenticationStatus.TOKEN_DELIEVERED.toString())){
                log.info("Token Already delievered.");
                return  true;


            } else {
                if(log.isDebugEnabled()){
                    log.info("User still not authenticated.Client can keep polling till authReqID expired.");
                }

                return false;
            }
        }








}
