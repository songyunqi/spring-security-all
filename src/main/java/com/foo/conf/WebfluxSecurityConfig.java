package com.foo.conf;

import com.foo.filter.PhoneCodeLoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.web.server.SecurityWebFilterChain;

import javax.annotation.Resource;
import java.util.LinkedList;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class WebfluxSecurityConfig {

    //查阅资料发现需要设置请求头为multipart/form-data格式,则在提交登录信息模块添加以下代码

    @Resource
    DefaultAuthenticationSuccessHandler successHandler;
    @Resource
    DefaultAuthenticationFailureHandler failureHandler;
    @Resource
    DefaultAccessDeniedHandler accessDeniedHandler;

    @Resource
    DefaultAuthenticationEntryPoint authenticationEntryPoint;
    @Resource
    DefaultSecurityContextRepository securityContextRepository;
    @Resource(name = "TokenAuthenticationManager")
    TokenAuthenticationManager tokenAuthenticationManager;
    //@Resource
    //PhoneCodeAuthenticationFilter phoneCodeAuthenticationFilter;
    @Resource
    private ReactiveUserDetailsService userDetailsService;
    /**
     * 自定义过滤权限
     */
    //@Value("${security.noFilter}")
    private String noFilter = "/login";

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        http.authenticationManager(reactiveAuthenticationManager())
                .securityContextRepository(securityContextRepository)
                // 请求拦截处理
                .authorizeExchange(
                        exchange -> exchange
                                .pathMatchers(noFilter, "/login", "/test", "/admin/test").permitAll()
                                //.pathMatchers(HttpMethod.OPTIONS).permitAll()
                                .pathMatchers("/admin/needRole").hasRole("admin")
                        //.anyExchange().access(defaultAuthorizationManager)
                ).formLogin().loginPage("/login")// 自定义登录页面
                .authenticationSuccessHandler(successHandler)
                .authenticationFailureHandler(failureHandler)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
                .and().addFilterAt(new PhoneCodeLoginFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .csrf().disable();
        return http.build();
    }

    /**
     * 注册用户信息验证管理器，可按需求添加多个按顺序执行
     */
    ReactiveAuthenticationManager reactiveAuthenticationManager() {
        List<ReactiveAuthenticationManager> managers = new LinkedList<>();
        //managers.add(authentication -> {
        // 其他登陆方式 (比如手机号验证码登陆) 可在此设置不得抛出异常或者 Mono.error
        //return Mono.empty();
        //});
        // 必须放最后不然会优先使用用户名密码校验但是用户名密码不对时此 AuthenticationManager 会调用 Mono.error 造成后面的 AuthenticationManager 不生效
        //managers.add(tokenAuthenticationManager);
        managers.add(new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService));
        return new DelegatingReactiveAuthenticationManager(managers);
    }
}


