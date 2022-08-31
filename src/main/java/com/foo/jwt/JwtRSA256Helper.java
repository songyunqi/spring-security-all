package com.foo.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class JwtRSA256Helper {

    //keytool -genkeypair -alias mytest -keyalg RSA -keypass mypass -keystore mytest.jks -storepass mypass
    private static final String JKS_FILE = "mytest.jks";
    private static final String ALIAS = "mytest";
    private static final String PASSWORD = "mypass";

    private static RSAPublicKey publicKey = null;
    private static RSAPrivateKey privateKey = null;

    static {
        try (InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(JKS_FILE)) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(stream, PASSWORD.toCharArray());
            privateKey = (RSAPrivateKey) keyStore.getKey(ALIAS, PASSWORD.toCharArray());
            publicKey = (RSAPublicKey) keyStore.getCertificate(ALIAS).getPublicKey();
        } catch (Exception e) {
            log.error("");
        }
    }

    public static void main(String[] args) {
        Map<String, Object> map = new HashMap<>(2);
        map.put("userId", "1");
        map.put("username", "admin");
        String token = create(map, 1000 * 60 * 30);
        System.out.println(token);
    }

    public static String create(Map<String, Object> payload, long expiration) {
        String token;
        try {
            Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
            Date expiredTime = new Date(System.currentTimeMillis() + expiration);
            token = JWT.create()
                    .withPayload(payload)
                    .withExpiresAt(expiredTime)
                    .sign(algorithm);
            return token;
        } catch (JWTCreationException exception) {
            log.error("JwtHelper create error:{}", exception.getMessage());
        }
        return null;
    }

    public static boolean verify(String token) {
        try {
            Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
            JWTVerifier verifier = JWT.require(algorithm)
                    .build();
            verifier.verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            log.error("RSA256JwtHelper verify error:{}", exception.getMessage());
        }
        return false;
    }

    public static Claim getClaim(String token, String key) {
        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT jwt = verifier.verify(token);
        return jwt.getClaim(key);
    }

    public static Map<String, Claim> getClaims(String token) {
        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT jwt = verifier.verify(token);
        return jwt.getClaims();
    }
}
