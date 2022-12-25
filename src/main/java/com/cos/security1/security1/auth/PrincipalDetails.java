package com.cos.security1.security1.auth;

import com.cos.security1.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

// 시큐리티가 /login을 낚아채서 로그인을 진행
// 로그인 진행이 완료가 되면 session을 만들어 준다(security context holder에 키값 저장)
// 시큐리티 세션의 오브젝트는 정해져 있다 => Authentication타입 객체다!
// Authentication안에는 User정보가 있어야 함(클래스가 정해져있다)
// User 오브젝트 타입은 UserDetails 타입 객체
// Security Session -> Authentication -> UserDetails(principalDetails)
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;

    private Map<String, Object> attributes;
    public PrincipalDetails(User user) {
        this.user = user;
    }

    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // 해당 유저의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getName() {
        return null;
    }
}
