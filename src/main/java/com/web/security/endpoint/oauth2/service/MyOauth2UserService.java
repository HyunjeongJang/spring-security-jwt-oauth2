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

import javax.persistence.EntityNotFoundException;

@Service
@RequiredArgsConstructor
public class MyOauth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final MemberRepository memberRepository;
    private final MemberService memberService;
    private final OAuth2AccountRepository oAuth2AccountRepository;

    @Transactional
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 1. AccessToken 이 발급되어서 넘어요면, 그걸로 사용자 정보 조회
        OAuth2UserService<OAuth2UserRequest, OAuth2User> userService = new DefaultOAuth2UserService();
        OAuth2User user = userService.loadUser(userRequest); // 이 시점에 토큰인증, 로그인 처리 다 한다음의 user 가 나옴

        // 2. 읽어온 사용자 정보로 현재 서비스에서 사용 가능한 Entity 를 만들어야 함 -> OAuth2Account
        OAuth2Account oAuth2Account = OAuth2Account.of(userRequest, user);

        // 3. 아직 가입되어 있지 않은 사용자라면 회원가입 시킴 -> Member 테이블에 정보를 넣기
        if(!memberRepository.existsByEmail(oAuth2Account.getEmail())) {
            // 가입이 되어있지 않으면, 가입을 시키고 가입시킨 사용자 정보를 조회해서 OAuth2Account 에 Member 를 채워서 저장
            memberService.register(RegisterRequest.from(oAuth2Account));
        }
        // 이미 가입 되어있으면 가입된 사용자 정보 조회 (OAuth2Account 에 Member 를 채워서 저장)
        Member member = memberRepository.findByEmail(oAuth2Account.getEmail())
                .orElseThrow(() -> new EntityNotFoundException("해당 이메일을 가진 사용자를 찾을 수 없습니다."));
        oAuth2Account.setMember(member);
        OAuth2Account savesAccount = oAuth2AccountRepository.save(oAuth2Account);

        // 4. OAuth2User 반환
        // -> Authentication 객체의 Principal 필드로 저장돼서 SuccessHandler 로 감
        return new MyOAuth2User(savesAccount);
    }
}
