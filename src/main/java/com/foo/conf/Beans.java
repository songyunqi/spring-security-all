package com.foo.conf;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class Beans {

    public static void main(String[] args) {
        String xx = PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("admin");
        System.out.println(xx);
    }

    @Bean
    public Gson gson() {
        return new GsonBuilder()
                .enableComplexMapKeySerialization()
                .disableHtmlEscaping()
                .create();
    }

    @Bean
    public PasswordEncoder bCryptPasswordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
