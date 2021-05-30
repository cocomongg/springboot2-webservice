package com.book.webservice.config.auth;

import com.book.webservice.config.auth.dto.OAuthAttributes;
import com.book.webservice.config.auth.dto.SessionUser;
import com.book.webservice.domain.user.User;
import com.book.webservice.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.Collections;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final UserRepository userRepository;
    private final HttpSession httpSession;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException{
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        System.out.println("getAttributes: " + oAuth2User.getAttributes());
        String registrationId = userRequest.getClientRegistration().getRegistrationId(); //현재 로그인 진행중인 서비스를 구분 하는 코드
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails() // OAuth2 로그인 진행 시 키가 되는 필드값 (Primary key와 같은 의미)
                                                .getUserInfoEndpoint().getUserNameAttributeName();

        OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        User user = saveOrUpdate(attributes);

        httpSession.setAttribute("user", new SessionUser(user)); //name과 value의 쌍으로 객체 Object를 저장하는 메소드,
                                                                       // 세션이 유지되는 동안 저장할 자료를 저장합니다.
        return new DefaultOAuth2User(Collections.singleton(new SimpleGrantedAuthority(user.getRoleKey())),
                                    attributes.getAttributes(),
                                    attributes.getNameAttributeKey());
     }

    private User saveOrUpdate(OAuthAttributes attributes){
        User user = userRepository.findByEmail(attributes.getEmail())
                        .map(entity -> entity.update(attributes.getName(), attributes.getPicture()))
                        .orElse(attributes.toEntity());

        return userRepository.save(user);
    }
}

