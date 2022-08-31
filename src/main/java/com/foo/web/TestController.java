package com.foo.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@Slf4j
public class TestController {

    @PostMapping("/test")
    public void test(@RequestParam("username") String username, @RequestParam("password") String password) {
        log.info("username:" + username);
        log.info("password:" + password);
    }

    @GetMapping("/admin/test")
    public Mono<String> adminTest() {
        return Mono.just("success : /admin/test");
    }

    @GetMapping("/admin/needRole")
    public Mono<String> needRole() {
        return Mono.just("success : /admin/test");
    }
}
