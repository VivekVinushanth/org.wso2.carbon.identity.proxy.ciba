package org.wso2.carbon.identity.proxy.ciba.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.wso2.carbon.identity.proxy.ciba.configuration.ConfigHandler;

import java.io.IOException;


@SpringBootApplication
public class ServerInstantiation extends SpringBootServletInitializer {


    public static void main(String[] args) throws IOException {

        SpringApplication.run(ServerInstantiation.class, args);
        ConfigHandler.getInstance().configure();


    }

}
