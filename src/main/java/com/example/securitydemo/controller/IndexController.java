package com.example.securitydemo.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author alan smith
 * @version 1.0
 * @date 2020/3/24 15:28
 */
@RestController
public class IndexController {

    @GetMapping("/index")
    public String index() {
        return "hello world";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/getUserInfo")
    public Object userInfo() {
        return SecurityContextHolder.getContext();
    }
}
