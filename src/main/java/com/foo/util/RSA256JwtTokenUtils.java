package com.foo.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class RSA256JwtTokenUtils {

    //设置过期时间
    private static final long EXPIRE_DATE = 30 * 60 * 100000;
    //token秘钥

    private static RSAPublicKey publicKey;// = //Get the key instance
    private static RSAPrivateKey privateKey;// = //Get the key instance

    static {
        try (InputStream INPUT_STREAM = Thread.currentThread().getContextClassLoader().getResourceAsStream("mirror-privateKey.jks");) {
            // java key store 固定常量
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(INPUT_STREAM, "3d-mirror".toCharArray());
            // jwt 为 命令生成整数文件时的别名
            privateKey = (RSAPrivateKey) keyStore.getKey("mirror-privateKey", "3d-mirror".toCharArray());
            publicKey = (RSAPublicKey) keyStore.getCertificate("mirror-privateKey").getPublicKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void xx() {
        try {
            Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
            String token = JWT.create()
                    .withIssuer("auth0")
                    .sign(algorithm);
            System.out.println(token);
        } catch (JWTCreationException exception) {
            //Invalid Signing configuration / Couldn't convert Claims.
        }
    }

    public static String token(String username, String password) {
        String token;
        try {
            Date date = new Date(System.currentTimeMillis() + EXPIRE_DATE);//过期时间
            Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);//秘钥及加密算法
            Map<String, Object> header = new HashMap<>();//设置头部信息
            header.put("type", "JWT");
            header.put("algs", "HS256");
            //携带username，password信息，生成签名
            token = JWT.create()
                    //.withHeader(header)
                    .withClaim("username", username)
                    .withClaim("password", password).withExpiresAt(date)
                    .sign(algorithm);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return token;
    }

    public static boolean verify(String token) {
        try {
            Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(token);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        String username = "test";
        String password = "123456";
        String token = token(username, password);
        System.out.println(token);
        boolean b = verify(token);
        System.out.println(b);
    }

    /*public static void main(String[] args) {
        try {
            JwkProvider provider = new UrlJwkProvider("https://appleid.apple.com/auth/keys");
            Jwk jwk = provider.get("<my-key-id>");
            String token = "<some-token-passed-from-client>";
            RSAPublicKey publicKey = (RSAPublicKey) jwk.getPublicKey();

            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("<my-issuer>")
                    .build();
            DecodedJWT jwt = verifier.verify(token);
        } catch (JWTVerificationException exception) {
            System.out.println("JWT Exception: " + exception.getMessage());
        } catch (JwkException e) {
            e.printStackTrace();
        }
    }*/
}
