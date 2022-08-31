package com.foo.conf;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class DefaultAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {
    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException e) {
        ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
        DataBufferFactory dataBufferFactory = response.bufferFactory();
        DataBuffer dataBuffer = dataBufferFactory.wrap(e.getMessage().getBytes());
        return response.writeWith(Mono.just(dataBuffer));
    }
}
