/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.proxy.ciba.handlers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.proxy.ciba.common.CibaParams;
import org.wso2.carbon.identity.proxy.ciba.dao.CibAuthCodeMgtDAO;
import org.wso2.carbon.identity.proxy.ciba.dto.AuthResponseContextDTO;
import org.wso2.carbon.identity.proxy.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.proxy.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.proxy.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.proxy.ciba.util.AuthReqIDManager;
import org.wso2.carbon.identity.proxy.ciba.util.AuthzRequestDOBuilder;
import org.wso2.carbon.identity.proxy.ciba.util.CibaAuthCodeDOBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.concurrent.ExecutionException;


/**
 *
 *This class handles authentication response.
 *
 * */
public class CibaAuthResponseHandler  {


    private static final Log log = LogFactory.getLog(CibaAuthResponseHandler.class);
    private CibaAuthResponseHandler() {

    }

    private static CibaAuthResponseHandler CibaAuthResponseHandlerInstance = new CibaAuthResponseHandler();

    public static CibaAuthResponseHandler getInstance() {
        if (CibaAuthResponseHandlerInstance == null) {

            synchronized (CibaAuthResponseHandler.class) {

                if (CibaAuthResponseHandlerInstance == null) {

                    /* instance will be created at request time */
                    CibaAuthResponseHandlerInstance = new CibaAuthResponseHandler();
                }
            }
        }
        return CibaAuthResponseHandlerInstance;

    }


    /**
     * This method create CIBA AuthenticationResponse.
     * @param cibaAuthRequestDTO CIBA Authentication Request Data Transfer Object
     * @return response
     * @throws ExecutionException,IOException
     */
    public Response createAuthResponse(@Context HttpServletRequest request, @Context HttpServletResponse response,
                                       CibaAuthRequestDTO cibaAuthRequestDTO) throws Exception {
        try {
            //create JWT as cibaauthcode response
        String  cibaAuthCode = AuthReqIDManager.getInstance().getCibaAuthCode(cibaAuthRequestDTO);

        //set the expirytime
        long expiresIn = AuthReqIDManager.getInstance().getExpiresIn(cibaAuthRequestDTO);


        //serialize so that can be returned in preferable manner

        if (log.isDebugEnabled()) {
            log.info("CIBA AuthReqID generated.");
            log.info("CIBA AuthReqID :"+cibaAuthCode);
        }

        //create authentication response
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON);
        OAuthResponse.OAuthResponseBuilder cibaAuthResponsebuilder = OAuthResponse.
                status(HttpServletResponse.SC_OK).setParam(CibaParams.AUTH_REQ_ID, cibaAuthCode).
                setParam(CibaParams.EXPIRES_IN,String.valueOf(expiresIn)).setParam(CibaParams.INTERVAL, "2");


        Response.ResponseBuilder respBuilder = Response.status(response.getStatus());

        OAuthResponse cibaAuthResponse = null;

            cibaAuthResponse = cibaAuthResponsebuilder.buildJSONMessage();

            //build authCode with all the parameters that need to be persisted
            CibaAuthCodeDO cibaAuthCodeDO = CibaAuthCodeDOBuilder.getInstance().buildCibaAuthCodeDO(cibaAuthCode,cibaAuthRequestDTO);
            // TODO: 10/14/19 can add as a builder format-

            //persist cibaAuthCode
            CibAuthCodeMgtDAO.getInstance().persistCibaAuthReqCode(cibaAuthCodeDO);

            //build authorize request data transfer object
            AuthzRequestDTO authzRequestDTO = AuthzRequestDOBuilder.getInstance().buildAuthzRequestDO(cibaAuthRequestDTO, cibaAuthCodeDO);
            // TODO: 10/14/19 can add as a builder format-

            //internal http authorize call to /authorize end point
            CibaAuthorizationHandler.getInstance().initiateAuthzRequest(authzRequestDTO);

            log.info("Returning CIBA Authentication Response.");
            return respBuilder.entity(cibaAuthResponse.getBody()).build();

        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in building authenticationResponse for Authentication Request.");

            }


        } catch (NoSuchAlgorithmException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (ExecutionException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (JOSEException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (InterruptedException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        }

        //return empty response
        return Response.noContent().build();
    }




    /**
     * This method create CIBA Authentication Error Response.
     * @param authResponseContextDTO CIBA AuthenticationResponseContext that accumulates error codes,error,description
     * @return response
     * @throws ExecutionException,IOException
     */
    public Response createErrorResponse(AuthResponseContextDTO authResponseContextDTO)
            throws OAuthSystemException {
        OAuthResponse errorresponse =  OAuthASResponse
                .errorResponse(authResponseContextDTO.getErrorCode())
                .setError(authResponseContextDTO.getError())
                .setErrorDescription(authResponseContextDTO.getErrorDescription())
                .buildJSONMessage();

        Response.ResponseBuilder respBuilder = Response.status(authResponseContextDTO.getErrorCode());
        return respBuilder.entity(errorresponse.getBody()).build();
    }


}
