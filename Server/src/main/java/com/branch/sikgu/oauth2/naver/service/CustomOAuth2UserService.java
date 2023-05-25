package com.branch.sikgu.oauth2.naver.service;

import com.branch.sikgu.auth.utils.CustomAuthorityUtils;
import com.branch.sikgu.member.entity.Member;
import com.branch.sikgu.member.repository.MemberRepository;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Service
public class CustomOAuth2UserService implements OAuth2UserService <OAuth2UserRequest, OAuth2User> {
    @Autowired
    MemberRepository memberRepository;

    @Autowired
    HttpSession httpSession;

    @Autowired
    CustomAuthorityUtils customAuthorityUtils;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {

        OAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(oAuth2UserRequest);

        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();

        String userNameAttributeName = oAuth2UserRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        String email;
        Map<String, Object> response = oAuth2User.getAttributes();

        if(registrationId.equals("naver")){
            Map<String, Object> hash = (Map<String, Object>) response.get("response");
            email = (String) hash.get("email");
        }else if(registrationId.equals("google")){
            email = (String) response.get("email");
        }else{
            throw new OAuth2AuthenticationException("허용되지 않은 인증입니다.");
        }


        Member member;
        Optional<Member> optionalMember = memberRepository.findByEmail(email);

        if(optionalMember.isPresent()){
            member = optionalMember.get();
        }else{
            member = new Member();
            member.setEmail(email);
            member.setRole(customAuthorityUtils.createRoles(email));
        }
        httpSession.setAttribute("member", member);

        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(member.getRole().toString()))
                        , oAuth2User.getAttributes()
                        , userNameAttributeName);
    }
}
