package com.cos.security1.security1.config;

import com.cos.security1.security1.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // Secured 어노테이션 활성화 / preAuthorize + postAuthorize 어노테이션 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .authorizeHttpRequests(auth -> {
                    try {
                        auth
                                .antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소
                                .antMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                                .antMatchers("/admin/**").hasAnyRole("ADMIN")
                                .anyRequest().permitAll()
                                .and()
                                .formLogin()
                                .loginPage("/loginForm")
                                .loginProcessingUrl("/login") // /login주소가 호출이 되면 시큐리티가 낚아채 대신 로그인 진행
                                .defaultSuccessUrl("/")
                                .and()
                                .oauth2Login()
                                .loginPage("/loginForm") // 1.코드받기(인증) 2.엑세스 토큰(권한) 3. 사용자 프로필 가져옴 4.그정도를 토대로 회원가입 자동으로 시키기
                                .userInfoEndpoint()
                                .userService(principalOauth2UserService);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .build();
    }
}
