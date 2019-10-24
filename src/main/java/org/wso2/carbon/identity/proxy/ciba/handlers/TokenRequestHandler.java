package org.wso2.carbon.identity.proxy.ciba.handlers;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.axis2.databinding.types.xsd.ID;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.wso2.carbon.identity.proxy.ciba.common.CibaParams;
import org.wso2.carbon.identity.proxy.ciba.configuration.ConfigurationFile;
import org.wso2.carbon.identity.proxy.ciba.dto.CibaResponseContextDTO;
import org.wso2.carbon.identity.proxy.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.proxy.ciba.util.RestTemplateFactory;
import org.wso2.carbon.identity.proxy.ciba.validator.TokenRequestValidator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

public class TokenRequestHandler {


    private static final Log log = LogFactory.getLog(TokenRequestHandler.class);
    private TokenRequestHandler() {

    }

    private static TokenRequestHandler TokenRequestHandlerInstance = new TokenRequestHandler();

    public static TokenRequestHandler getInstance() {
        if (TokenRequestHandlerInstance == null) {

            synchronized (TokenRequestHandler.class) {

                if (TokenRequestHandlerInstance == null) {

                    /* instance will be created at request time */
                    TokenRequestHandlerInstance = new TokenRequestHandler();
                }
            }
        }
        return TokenRequestHandlerInstance;

    }



    public Response receive(@Context HttpServletRequest request , @Context HttpServletResponse response) throws Exception {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        CibaResponseContextDTO cibaResponseContextDTO = new CibaResponseContextDTO();

        if(TokenRequestValidator.getInstance().isValidTokenRequest(request,cibaResponseContextDTO,cibaAuthCodeDO)){
           return this.getTokenFromIS(cibaAuthCodeDO.getCibaAuthCodeID(),response);
        } else {
            return this.returnErrorResponse(cibaResponseContextDTO);
        }

    }

    private Response returnErrorResponse(CibaResponseContextDTO cibaResponseContextDTO) throws OAuthSystemException {
        OAuthResponse errorresponse =  OAuthASResponse
                .errorResponse(cibaResponseContextDTO.getErrorCode())
                .setError(cibaResponseContextDTO.getError())
                .setErrorDescription(cibaResponseContextDTO.getErrorDescription())
                .buildJSONMessage();

        Response.ResponseBuilder respBuilder = Response.status(cibaResponseContextDTO.getErrorCode());
        return respBuilder.entity(errorresponse.getBody()).build();
    }


    public Response getTokenFromIS(String authCodeID,@Context HttpServletResponse response) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, ParseException, OAuthSystemException {
        RestTemplate restTemplate = RestTemplateFactory.getInstance().getRestTemplate();

        //headers set
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth(ConfigurationFile.getInstance().getCLIENT_ID(), ConfigurationFile.getInstance().getCLIENT_SECRET());
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);


        MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
        map.add("grant_type", ConfigurationFile.getInstance().getGRANT_TYPE());
        map.add("auth_req_id", authCodeID);
        map.add("redirect_uri", ConfigurationFile.getInstance().getCLIENT_NOTIFICATION_ENDPOINT());


        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<MultiValueMap<String, String>>(map, headers);

        String token = restTemplate.postForObject("https://localhost:9443/oauth2/token", request, String.class);
        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(token);

       String IDToken = String.valueOf(json.get("id_token"));
        String refreshToken = String.valueOf(json.get("refresh_token"));
        String  accessToken = String.valueOf(json.get("access_token"));
        String expiresIn = String.valueOf(json.get("expires_in"));
        String scope = String.valueOf(json.get("scope"));


        response.setStatus(HttpServletResponse.SC_OK);
        OAuthResponse.OAuthResponseBuilder cibaTokenResponsebuilder = OAuthResponse.
                status(HttpServletResponse.SC_OK).
                setParam("id_token", IDToken).
                setParam("access_token",accessToken).
                setParam("refresh_token",refreshToken).
                setParam("expires_in",expiresIn).
                setParam("scope",scope);

        OAuthResponse cibaTokenResponse = null;

        cibaTokenResponse = cibaTokenResponsebuilder.buildJSONMessage();

        Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
        return respBuilder.entity(cibaTokenResponse.getBody()).build();
    }
}
