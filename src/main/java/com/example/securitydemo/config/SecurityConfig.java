package com.example.securitydemo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.PrintWriter;

/**
 * @author alan smith
 * @version 1.0
 * @date 2020/3/24 15:36
 */
@Configuration
// 启动 spring security 的 web 安全支持
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 将用户设置在内存中
     *
     * @param auth 封装认证的信息
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 获取加密者
        PasswordEncoder passwordEncoder = passwordEncoder();

        // 在内存中写入用户信息
        auth.inMemoryAuthentication()
                // 指定加密方式
                .passwordEncoder(passwordEncoder)
                // 录入 admin 用户信息，自定义 ADMIN 权限
                .withUser("admin").password(passwordEncoder.encode("123456")).roles("ADMIN")
                .and()
                // 录入 test 用户信息，自定义 USER 权限
                .withUser("test").password(passwordEncoder.encode("111111")).roles("USER");
    }

    private PasswordEncoder passwordEncoder() {
        // return new MessageDigestPasswordEncoder("MD5")
        // or
        // BCryptPasswordEncoder: Spring Security 提供的加密工具，可快速实现加密加盐
        return new BCryptPasswordEncoder();
    }

    /**
     * 忽略拦截
     *
     * @param web 对web请求的封装
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        // 设置拦截忽略 url - 会直接过滤改url - 将不会经过 Spring Security 过滤器链
        web
                // 设置拦截忽略文件夹，请求 url 匹配则不拦截
                .ignoring().antMatchers("/favicon.ico")
                .and()
                // 可以对静态资源放行
                .ignoring().antMatchers("/css/**", "/js/**");
    }

    /**
     * 登录处理
     *
     * @param http 对http请求和响应的封装
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 开启登录匹配
        http.authorizeRequests()
                // 标识访问 '/index' 这个接口，需要具备 ADMIN 角色
                .antMatchers("/index").hasRole("ADMIN")
                // 设置可匿名匿名访问的标识
                .antMatchers("/", "/home").permitAll()
                // 其余所有请求都需要认证
                .anyRequest().authenticated()

                .and()

                // 设置登录认证页面
                .formLogin()
                // 配置(自定义的)登录页面的 url
                //.loginPage("/login")
                // 自定义登录用户名和密码的属性名，默认为 username 和 password
                .usernameParameter("username1")
                .passwordParameter("password1")
                // 登录后的(默认)转跳 - 方式1
                .loginProcessingUrl("/home")
                // 登录后的(默认)转跳 - 方式2
                .successHandler((req, resp, authentication) -> {
                    //resp.sendRedirect("/home");
                    System.out.println(SecurityContextHolder.getContext());
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write("登录成功...");
                    out.flush();
                })
                // 配置登录失败的回调 - 方式1
                //.failureForwardUrl("/home")
                // 配置登录失败的回调 - 方式2
                .failureHandler((req, resp, exception) -> {
                    resp.setContentType("application/json;carset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write("登录失败...");
                    out.flush();
                })
                // 和表单登录相关的接口统统都自接通过
                .permitAll()

                .and()

                .logout()
                .logoutUrl("/logout")
                // 配置注销成功的回调
                .logoutSuccessHandler((req, resp, authentication) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write("注销成功...");
                    out.flush();
                })
                .permitAll()

                .and()
                // 开启 http basic 认证
                .httpBasic()
                .and()
                // 关闭 csrf 跨域
                .csrf().disable();


    }
}
