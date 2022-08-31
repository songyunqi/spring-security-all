package com.foo.conf;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component("UserDetailsServiceImpl")
@Slf4j
public class UserDetailsServiceImpl implements ReactiveUserDetailsService {

    @Value("${usersByUsernameQuery}")
    private String usersByUsernameQuery;

    @Value("${authoritiesByUserIdQuery}")
    private String authoritiesByUserIdQuery;
    @Value("${rolePrefix}")
    private String rolePrefix;
    @Value("${enableGroups}")
    private boolean enableGroups;
    @Value("${enableAuthorities}")
    private boolean enableAuthorities;

    @Resource
    private NamedParameterJdbcOperations queryContext;

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        Map<String, Object> params = new HashMap<>(6);
        params.put("username", username);
        Map<String, Object> resultMap = queryContext.queryForMap(usersByUsernameQuery, params);
        if (CollectionUtils.isEmpty(resultMap)) {
            throw new UsernameNotFoundException("username:" + username + " not found.");
        }
        String password = String.valueOf(resultMap.get("password"));
        String userId = String.valueOf(resultMap.get("userId"));
        params.put("userId", userId);
        List<Map<String, Object>> authoritiesList = queryContext.queryForList(authoritiesByUserIdQuery, params);
        Collection<? extends GrantedAuthority> authorities = authoritiesList
                .stream()
                .map(m -> new SimpleGrantedAuthority(String.valueOf(m.get("role_name"))))
                .collect(Collectors.toSet());

        User user = new DefaultUserDetails(userId,
                username,
                password,
                authorities);
        /*User user = new DefaultUserDetails("1",
                "admin",
                "{bcrypt}$2a$10$Tr1DPx3M8xs3NnXEmstvmuTkTgCDRCwjBoIvmEtVFH2yvRn3qYQTi",
                new ArrayList<>());*/
        return Mono.just(user);
    }
}
