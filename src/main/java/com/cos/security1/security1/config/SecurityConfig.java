package com.cos.security1.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 해당 메소드의 리턴되는 오브젝트를 IOC로 등록해줌
    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .authorizeHttpRequests(auth -> {
                    try {
                        auth
                                .antMatchers("/user/**").authenticated()
                                .antMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                                .antMatchers("/admin/**").hasAnyRole("ADMIN")
                                .anyRequest().permitAll()
                                .and()
                                .formLogin()
                                .loginPage("/loginForm");
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .build();
    }
}
