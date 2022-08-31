package com.foo.filter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

//用component导致多次调用
@Slf4j
public class PhoneCodeLoginFilter implements WebFilter {

    private static final Gson gson = new GsonBuilder().enableComplexMapKeySerialization().disableHtmlEscaping().create();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        Mono<MultiValueMap<String, String>> formData = exchange.getFormData();
        MultiValueMap<String, String> queryParams = request.getQueryParams();
        DataBufferFactory dataBufferFactory = response.bufferFactory();
        log.info("get request:{}", request);
        log.info("get response:{}", response);
        log.info("get formData:{}", formData);
        log.info("get queryParams:{}", queryParams);
        return formData.flatMap(form -> {
            String phoneNum = form.getFirst("phoneNum");
            String verifyCode = form.getFirst("verifyCode");
            String orgVerifyCode = "123456";
            JsonObject jsonObject = new JsonObject();
            if (StringUtils.isEmpty(phoneNum)) {
                jsonObject.addProperty("phoneNum", "phoneNum is empty.");
                DataBuffer dataBuffer = dataBufferFactory.wrap(gson.toJson(jsonObject).getBytes());
                return response.writeWith(Mono.just(dataBuffer));
            }
            if (!StringUtils.equalsIgnoreCase(verifyCode, orgVerifyCode)) {
                jsonObject.addProperty("phoneNum", "verifyCode is correct.");
                DataBuffer dataBuffer = dataBufferFactory.wrap(gson.toJson(jsonObject).getBytes());
                return response.writeWith(Mono.just(dataBuffer));
            }
            List<? extends GrantedAuthority> authorities = new ArrayList<>();
            AbstractAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(phoneNum, null, authorities);
            log.trace("Set security context {}", authentication);
            //这句话将认证数据传递给认证管理器
            return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        });
    }
}
