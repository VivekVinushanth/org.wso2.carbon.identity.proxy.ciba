package org.wso2.carbon.identity.proxy.ciba.server;


import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.proxy.ciba.common.CibaParams;
import org.wso2.carbon.identity.proxy.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.proxy.ciba.handlers.CibaAuthRequestHandler;

import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;


/**
 * This class is the actual implementation of CIBA proxy server.
 */

@RestController
public class CIBAProxyServer implements AuthorizationServer {

    /** List of Observers.
     * Interested in the incoming requests
     */

    private static final Log log = LogFactory.getLog(CibaAuthRequestHandler.class);

    public CIBAProxyServer()  {

    }


    /**
     * Endpoint where authentication request hits and then proceeded.
     */
    @RequestMapping(value = "/CIBAEndPoint")
    public Response acceptAuthRequest(@Context HttpServletRequest request , @Context HttpServletResponse response)
            throws OAuthSystemException, ParseException, IdentityOAuth2Exception {
        Map<String, String[]> attributeNames = request.getParameterMap();
        //capture all parameters


        log.info("CIBA request has hit Client Initiated Back-Channel Authentication EndPoint.");


            if (attributeNames.containsKey(CibaParams.REQUEST)) {
                //only allow signed request - check for existence of 'request' parameter.
                if (log.isDebugEnabled()) {
                    log.debug("CIBA request has the 'request' parameter.");
                }

                return CibaAuthRequestHandler.getInstance().handleAuthRequest(request,response);

            } else {
                if (log.isDebugEnabled()) {
                    log.debug("CIBA request has no 'request' parameter.");
                }
                //create error response since there is no 'request' parameter which is a must in signed request.
                OAuthResponse errorresponse;
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

                errorresponse = OAuthASResponse
                        .errorResponse(response.getStatus())
                        .setError(ErrorCodes.INVALID_REQUEST)
                        .setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS)
                        .buildJSONMessage();


                Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
                return respBuilder.entity(errorresponse.getBody()).build();

            }

    }

        /**
     *Endpoint where token request hits and then proceeded.
     */
    @RequestMapping(value= "/TokenEndPoint")
    public void acceptTokenRequest(@Context HttpServletRequest request , @Context HttpServletResponse response) {


    }



    /**
     *Endpoint which serves as Callbackurl.
     */
    @RequestMapping("/CallBackEndpoint")
    public void acceptAuthenticationStatus(@Context HttpServletRequest request , @Context HttpServletResponse response) {
            // TODO: 10/23/19 implement
    }


    /**
     *Endpoint through which  client app can be registered.
     */
    @RequestMapping("/RegistrationEndPoint")
    public void acceptRegistrationRequest(@Context HttpServletRequest request , @Context HttpServletResponse response) {

        //no implementation
    }

    /**
     *Endpoint where token request hits and then proceeded.
     */
    @RequestMapping("/UserRegistrationEndPoint")
    public void acceptUserRegistration(@Context HttpServletRequest request , @Context HttpServletResponse response) {

        //no implementation

    }


}

