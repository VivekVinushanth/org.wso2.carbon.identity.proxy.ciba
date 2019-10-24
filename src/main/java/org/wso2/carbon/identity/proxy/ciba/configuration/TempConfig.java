package org.wso2.carbon.identity.proxy.ciba.configuration;

public class TempConfig {
    public TempConfig(){}
    private  String appName;
    private  String clientId;
    private  String clientSecret;
    /*private  String authorizationUser;
    private  String authorizationPassword;*/
    private  String storeConnectorType;
    private  String dbUserName;
    private  String dbUserPassword;
    private  String database;
    private  String flowMode;
    private  String clientNotificationEndpoint;
    private String privateKey;
    private String grant_type;

    public String getGrant_type() {
        return grant_type;
    }

    public void setGrant_type(String grant_type) {
        this.grant_type = grant_type;
    }


    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getClientNotificationEndpoint() {
        return clientNotificationEndpoint;
    }

    public void setClientNotificationEndpoint(String clientNotificationEndpoint) {
        this.clientNotificationEndpoint = clientNotificationEndpoint;
    }

    public String getflowMode() {
        return flowMode;
    }

    public void setflowMode(String flowMode) {
        this.flowMode = flowMode;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }


/*
    public String getAuthorizationUser() {
        return authorizationUser;
    }

    public void setAuthorizationUser (String authorizationUser) {
        this.authorizationUser = authorizationUser;
    }

    public String getAuthorizationPassword() {
        return authorizationPassword;
    }

    public void setAuthorizationPassword(String authorizationPassword) {
        this.authorizationPassword = authorizationPassword;
    }*/

    public String getStoreConnectorType() {
        return storeConnectorType;
    }

    public void setStoreConnectorType(String storeConnectorType) {
        this.storeConnectorType = storeConnectorType;
    }

    public String getDbUserName() {
        return dbUserName;
    }

    public void setDbUserName(String dbUserName) {
        this.dbUserName = dbUserName;
    }

    public String getDbUserPassword() {
        return dbUserPassword;
    }

    public void setDbUserPassword(String dbUserPassword) {
        this.dbUserPassword = dbUserPassword;
    }

    public String getDatabase() {
        return database;
    }

    public void setDatabase(String database) {
        this.database = database;
    }


}
