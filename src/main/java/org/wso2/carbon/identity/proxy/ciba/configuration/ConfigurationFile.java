package org.wso2.carbon.identity.proxy.ciba.configuration;


import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class ConfigurationFile {
    public ConfigurationFile() {

    }

    private static ConfigurationFile configurationFileInstance = new ConfigurationFile();

    public static ConfigurationFile getInstance() {
        if (configurationFileInstance == null) {

            synchronized (ConfigurationFile.class) {

                if (configurationFileInstance == null) {

                    /* instance will be created at request time */
                    configurationFileInstance = new ConfigurationFile();
                }
            }
        }
        return configurationFileInstance;


    }


    private  String APP_NAME;
    private  String CLIENT_ID;
    private  String CLIENT_SECRET;
    private  String SEC_TOKEN;
  /*  private  String AUTHORIZATION_USER;
    private  String AUTHORIZATION_PASSWORD;*/
    private  String STORE_CONNECTOR_TYPE; // TODO: 8/28/19 important place for shifting the dao object
    private  String DB_USER_NAME;
    private  String DB_PASSWORD ;
    private  String DATABASE;
    private  String FLOW_MODE;
    private  String CLIENT_NOTIFICATION_ENDPOINT;
    private String PRIVATE_KEY;
    private String GRANT_TYPE;

    public String getGRANT_TYPE() {
        return GRANT_TYPE;
    }

    public void setGRANT_TYPE(String GRANT_TYPE) {
        this.GRANT_TYPE = GRANT_TYPE;
    }

    public String getPRIVATE_KEY() {
        return PRIVATE_KEY;
    }

    public void setPRIVATE_KEY(String PRIVATE_KEY) {
        this.PRIVATE_KEY = PRIVATE_KEY;
    }

    public String getCLIENT_NOTIFICATION_ENDPOINT() {
        return CLIENT_NOTIFICATION_ENDPOINT;
    }

    public void setCLIENT_NOTIFICATION_ENDPOINT(String CLIENT_NOTIFICATION_ENDPOINT) {
        this.CLIENT_NOTIFICATION_ENDPOINT = CLIENT_NOTIFICATION_ENDPOINT;
    }




    public String getFLOW_MODE() {
        return FLOW_MODE;
    }

    public void setFLOW_MODE(String FLOW_MODE) {
        this.FLOW_MODE = FLOW_MODE;
    }



    public String getAPP_NAME() {
        return APP_NAME;
    }

    public void setAPP_NAME(String APP_NAME) {
        this.APP_NAME = APP_NAME;
    }

    public String getCLIENT_ID() {
        return CLIENT_ID;
    }

    public void setCLIENT_ID(String CLIENT_ID) {
        this.CLIENT_ID = CLIENT_ID;
    }

    public String getCLIENT_SECRET() {
        return CLIENT_SECRET;
    }

    public void setCLIENT_SECRET(String CLIENT_SECRET) {
        this.CLIENT_SECRET = CLIENT_SECRET;
    }

    public void setSEC_TOKEN(String SEC_TOKEN) {
        this.SEC_TOKEN = SEC_TOKEN;
    }

 /*   public String getAUTHORIZATION_USER() {
        return AUTHORIZATION_USER;
    }

    public void setAUTHORIZATION_USER(String AUTHORIZATION_USER) {
        this.AUTHORIZATION_USER = AUTHORIZATION_USER;
    }

    public String getAUTHORIZATION_PASSWORD() {
        return AUTHORIZATION_PASSWORD;
    }

    public void setAUTHORIZATION_PASSWORD(String AUTHORIZATION_PASSWORD) {
        this.AUTHORIZATION_PASSWORD = AUTHORIZATION_PASSWORD;
    }*/

    public String getSTORE_CONNECTOR_TYPE() {
        return STORE_CONNECTOR_TYPE;
    }

    public void setSTORE_CONNECTOR_TYPE(String STORE_CONNECTOR_TYPE) {
        this.STORE_CONNECTOR_TYPE = STORE_CONNECTOR_TYPE;
    }

    public String getDB_USER_NAME() {
        return DB_USER_NAME;
    }

    public void setDB_USER_NAME(String DB_USER_NAME) {
        this.DB_USER_NAME = DB_USER_NAME;
    }

    public String getDB_PASSWORD() {
        return DB_PASSWORD;
    }

    public void setDB_PASSWORD(String DB_PASSWORD) {
        this.DB_PASSWORD = DB_PASSWORD;
    }

    public String getDATABASE() {
        return DATABASE;
    }

    public void setDATABASE(String DATABASE) {
        this.DATABASE = DATABASE;
    }



    public String getSEC_TOKEN() {
        return SEC_TOKEN;
    }

    public void setSEC_TOKEN(String AUTHORIZATION_USER ,String AUTHORIZATION_PASSWORD) throws UnsupportedEncodingException {

        this.SEC_TOKEN = Base64.getEncoder().encodeToString((AUTHORIZATION_USER+":"+AUTHORIZATION_PASSWORD).getBytes("utf-8"));
       // System.out.println("Sec token here :"+SEC_TOKEN);
    }


}
