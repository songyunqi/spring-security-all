package com.foo.conf;

import com.auth0.jwt.interfaces.Claim;
import com.foo.jwt.JwtRSA256Helper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component("TokenAuthenticationManager")
@Slf4j
public class TokenAuthenticationManager implements ReactiveAuthenticationManager {

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (null == principal) {
            return Mono.empty();
        }
        Map<String, Claim> claims = null;
        try {
            claims = JwtRSA256Helper.getClaims(principal.toString());
        } catch (Exception ex) {
            log.error("TokenAuthenticationManager error:{}", ex.getMessage());
        }
        if (null == claims) {
            return Mono.empty();
        }
        String username = claims.get("username").asString();
        List<String> roles = null;
        if (null != claims.get("roles")) {
            roles = claims.get("roles").asList(String.class);
        }
        Collection<? extends GrantedAuthority> authorities = null;
        if (!CollectionUtils.isEmpty(roles)) {
            authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        }
        //principal实际就是username
        //从principal 中解析出jwt
        Authentication auth = new UsernamePasswordAuthenticationToken(
                username,
                null,
                authorities);
        return Mono.just(auth);
    }
}
