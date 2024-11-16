package com.example.springsecurityoauth2example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class SpringSecurityOauth2ExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityOauth2ExampleApplication.class, args);
    }

}
