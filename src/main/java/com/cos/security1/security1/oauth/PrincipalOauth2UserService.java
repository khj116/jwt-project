package com.cos.security1.security1.oauth;

import com.cos.security1.security1.auth.PrincipalDetails;
import com.cos.security1.security1.model.User;
import com.cos.security1.security1.oauth.provider.GoogleUserInfo;
import com.cos.security1.security1.oauth.provider.NaverUserInfo;
import com.cos.security1.security1.oauth.provider.Oauth2UserInfo;
import com.cos.security1.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {


    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private UserRepository userRepository;

    // 함수가 종료되면 @AuthenticationPrincipal 생성
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 구글 로그 버튼 -> 구글 로그인 창 -> 로그인 완료 -> code 리턴(Oauth - Client 라이브러리) -> AccessToken 요청
        // userRequest 정보 -> loadUser 함수로 회원 프로필 얻을 수 있음
        // 구글로 부터 userRequest 데이터 받음
        OAuth2User oauth2User = super.loadUser(userRequest);
        Oauth2UserInfo oauth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
            oauth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            oauth2UserInfo = new NaverUserInfo((Map) oauth2User.getAttributes().get("response"));
        }

        String provider = oauth2UserInfo.getProvider();
        String providerId = oauth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String password = bCryptPasswordEncoder.encode("password");
        String email = oauth2UserInfo.getEmail();
        String role ="ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if(userEntity == null){ 
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }
        return new PrincipalDetails(userEntity);
    }
}
