package org.wso2.carbon.identity.proxy.ciba.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.proxy.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.proxy.ciba.common.CibaParams;
import org.wso2.carbon.identity.proxy.ciba.dao.CibaAuthResponseMgtDAO;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import java.util.Map;

public class CibaCallBackHandler {


    private static final Log log = LogFactory.getLog(CibaCallBackHandler.class);

    private CibaCallBackHandler() {

    }

    private static CibaCallBackHandler CibaCallBackHandlerInstance = new CibaCallBackHandler();

    public static CibaCallBackHandler getInstance() {
        if (CibaCallBackHandlerInstance == null) {

            synchronized (CibaCallBackHandler.class) {

                if (CibaCallBackHandlerInstance == null) {

                    /* instance will be created at request time */
                    CibaCallBackHandlerInstance = new CibaCallBackHandler();
                }
            }
        }
        return CibaCallBackHandlerInstance;
    }



    public void handleCallBackfromIS(@Context HttpServletRequest request) throws Exception {
        Map<String, String[]> attributeNames = request.getParameterMap();
        String cibaAuthCodeID = request.getParameter("nonce");

        if(attributeNames.containsKey(CibaParams.ERROR_DESCRIPTION)){
            CibaAuthResponseMgtDAO.getInstance().persistStatus(cibaAuthCodeID, AuthenticationStatus.DENIED.toString());

        } else if (attributeNames.containsKey(CibaParams.SESSION_STATE)){
            CibaAuthResponseMgtDAO.getInstance().persistStatus(cibaAuthCodeID, AuthenticationStatus.AUTHENTICATED.toString());

        } else{
            //do nothing
        }

    }
}
