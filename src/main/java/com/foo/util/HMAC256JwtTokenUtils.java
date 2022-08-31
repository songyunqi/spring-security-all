package com.foo.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.SneakyThrows;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class HMAC256JwtTokenUtils {
    //设置过期时间
    private static final long EXPIRE_DATE = 30 * 60 * 100000;
    //token秘钥
    private static final String TOKEN_SECRET = "ZCfasfhuaUUHufguGuwu2020BQWE";
    private static final Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);

    @SneakyThrows
    public static String genToken(Map<String, Object> header, Map<String, Object> payload) {
        Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
        Date date = new Date(System.currentTimeMillis() + EXPIRE_DATE);//过期时间
        String token = JWT.create()
                .withHeader(header)
                .withPayload(payload)
                .withExpiresAt(date)
                .sign(algorithm);
        return token;
    }

    @SneakyThrows
    public static Claim getClaim(String token, String key) {
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT jwt = verifier.verify(token);
        return jwt.getClaim(key);
    }

    public static boolean verify(String token) {
        Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
        try {
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        String username = "admin";
        String password = "admin";
        Map<String, Object> header = new HashMap<>();
        Map<String, Object> payload = new HashMap<>();
        payload.put("username", username);
        payload.put("password", password);
        String token = genToken(header, payload);
        System.out.println(token);
        boolean b = verify(token);
        System.out.println(b);
        Claim claim = getClaim(token, "username");
        System.out.println(claim.asString());
    }
}
