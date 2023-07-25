package com.web.security.endpoint.oauth2.service;

import com.web.security.domain.entity.Member;
import com.web.security.domain.entity.OAuth2Account;
import com.web.security.domain.repository.MemberRepository;
import com.web.security.domain.repository.OAuth2AccountRepository;
import com.web.security.endpoint.member.dto.RegisterRequest;
import com.web.security.endpoint.member.service.MemberService;
import com.web.security.endpoint.oauth2.dto.MyOAuth2User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MyOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final MemberRepository memberRepository;
    private final MemberService memberService;
    private final OAuth2AccountRepository oAuth2AccountRepository;

    @Transactional
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2UserService<OAuth2UserRequest, OAuth2User> userService = new DefaultOAuth2UserService();
        OAuth2User user = userService.loadUser(userRequest);
        OAuth2Account oAuth2Account = OAuth2Account.of(userRequest, user);

        if(!memberRepository.existsByEmail(oAuth2Account.getEmail())) {
            memberService.register(RegisterRequest.from(oAuth2Account));
        }
        Member member = memberRepository.getByEmail(oAuth2Account.getEmail());
        oAuth2Account.setMember(member);
        if (!oAuth2AccountRepository.existsByProviderNameAndAccountId(oAuth2Account.getProviderName(), oAuth2Account.getAccountId())) {
            oAuth2AccountRepository.save(oAuth2Account);
        }
        return new MyOAuth2User(oAuth2Account);
    }

}

