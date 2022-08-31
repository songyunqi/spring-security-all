package com.foo.conf;

import com.foo.jwt.JwtRSA256Helper;
import com.google.gson.Gson;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class DefaultAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

    @Resource
    private Gson gson;

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
        DataBufferFactory dataBufferFactory = response.bufferFactory();
        DefaultUserDetails userDetails = (DefaultUserDetails) authentication.getPrincipal();
        List<String> authorityList = null;
        if (!CollectionUtils.isEmpty(userDetails.getAuthorities())) {
            authorityList = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        }
        Map<String, Object> map = new HashMap<>(2);
        map.put("userId", userDetails.getUserId());
        map.put("username", userDetails.getUsername());
        if (!CollectionUtils.isEmpty(authorityList)) {
            map.put("roles", authorityList);
        }
        String token = JwtRSA256Helper.create(map, 1000 * 60 * 30);
        String refreshToken = JwtRSA256Helper.create(map, 1000 * 60 * 60 * 24 * 14);
        map.put("token", token);
        map.put("refreshToken", refreshToken);
        DataBuffer dataBuffer = dataBufferFactory.wrap(gson.toJson(map).getBytes());
        return response.writeWith(Mono.just(dataBuffer));
    }
}
