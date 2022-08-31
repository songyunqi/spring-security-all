package com.foo.conf;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.util.List;

@Component
public class DefaultSecurityContextRepository implements ServerSecurityContextRepository {

    public final static String TOKEN_HEADER = "Authorization";

    @Resource(name = "TokenAuthenticationManager")
    TokenAuthenticationManager tokenAuthenticationManager;

    @Override
    public Mono<Void> save(ServerWebExchange serverWebExchange, SecurityContext securityContext) {
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        List<String> headers = request.getHeaders().get(TOKEN_HEADER);
        if (CollectionUtils.isEmpty(headers)) {
            return Mono.empty();
        }
        String authorization = headers.get(0);
        if (StringUtils.isEmpty(authorization)) {
            return Mono.empty();
        }
        //String token = authorization.substring(BEARER.length());
        //if (StringUtils.isEmpty(token)) {
        //return Mono.empty();
        //}
        return tokenAuthenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(authorization, null)
                )
                .map(SecurityContextImpl::new);
    }
}
