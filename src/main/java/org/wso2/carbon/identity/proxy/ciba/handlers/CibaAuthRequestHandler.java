package org.wso2.carbon.identity.proxy.ciba.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.proxy.ciba.common.CibaParams;
import org.wso2.carbon.identity.proxy.ciba.dto.AuthResponseContextDTO;
import org.wso2.carbon.identity.proxy.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.proxy.ciba.validator.AuthRequestValidator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.text.ParseException;


/**
     *
     *This class handles authentication response.
     *
     * */
    public class CibaAuthRequestHandler  {


        private static final Log log = LogFactory.getLog(CibaAuthRequestHandler.class);
        private CibaAuthRequestHandler() {

        }

        private static CibaAuthRequestHandler CibaAuthRequestHandlerInstance = new CibaAuthRequestHandler();

        public static CibaAuthRequestHandler getInstance() {
            if (CibaAuthRequestHandlerInstance == null) {

                synchronized (CibaAuthRequestHandler.class) {

                    if (CibaAuthRequestHandlerInstance == null) {

                        /* instance will be created at request time */
                        CibaAuthRequestHandlerInstance = new CibaAuthRequestHandler();
                    }
                }
            }
            return CibaAuthRequestHandlerInstance;

        }


        public Response handleAuthRequest(@Context HttpServletRequest request,@Context HttpServletResponse response)
                throws ParseException, OAuthSystemException, IdentityOAuth2Exception {
            String authRequest = request.getParameter(CibaParams.REQUEST);

            CibaAuthRequestDTO cibaAuthRequestDTO = new CibaAuthRequestDTO(); //new DTO to capture claims in request

            AuthResponseContextDTO authResponseContextDTO = new AuthResponseContextDTO();

            if (AuthRequestValidator.getInstance().isValidClient(authRequest, authResponseContextDTO, cibaAuthRequestDTO)) {
                //check whether the client exists

                if (AuthRequestValidator.getInstance().isValidUser(authRequest, authResponseContextDTO, cibaAuthRequestDTO)) {
                    //check whether the user exists

                    if (AuthRequestValidator.getInstance().isValidUserCode(authRequest, authResponseContextDTO)) {
                        //extensible method to validate usercode if needed


                        if (AuthRequestValidator.getInstance().isValidAuthRequest
                                (authRequest, authResponseContextDTO, cibaAuthRequestDTO)) {
                            //validate authentication request for existence of mandatory parameters and values
                            try {
                                return CibaAuthResponseHandler.getInstance().
                                        createAuthResponse(request, response, cibaAuthRequestDTO);
                                //if valid request - create a ciba authentication response

                            } catch (NullPointerException e) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Unable to create AuthenticationResponse.", e);
                                }

                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } else {
                            try {
                                return CibaAuthResponseHandler.getInstance().
                                        createErrorResponse(authResponseContextDTO);
                                //if invalid request - create a ciba error response


                            } catch (NullPointerException e) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Unable to create AuthenticationResponse.", e);
                                }
                            }
                        }
                    } else {

                        return CibaAuthResponseHandler.getInstance().createErrorResponse(authResponseContextDTO);
                    }
                } else {


                    return CibaAuthResponseHandler.getInstance().createErrorResponse(authResponseContextDTO);
                }
            } else {


                return CibaAuthResponseHandler.getInstance().createErrorResponse(authResponseContextDTO);
            }

            return null;
        }
}
