package com.web.security.domain.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;

import javax.persistence.*;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Table(name = "oauth2_account")
public class OAuth2Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "oauth2_account_id")
    private Long id;

    private String providerName;
    private String accountId;

    @JoinColumn(name = "member_id", referencedColumnName = "member_id")
    @ManyToOne(fetch = FetchType.LAZY)
    private Member member;

    @Transient // 컬럼으로 인식하지 않고 단순 데이터를 담기위한 목적
    private String email;

    @Transient
    private String nickname;

    public static OAuth2Account of(OAuth2UserRequest request, OAuth2User user) {
        String registrationId = request.getClientRegistration().getRegistrationId(); // kakao (yml - registration 부분)
        String attributeName = request.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        OAuth2Account oAuth2Account = null;
        if(registrationId.equals("kakao")) {
            oAuth2Account = OAuth2Account.ofKakao(user, registrationId, attributeName);
        }
//        else if (registrationId.equals("naver")) {
//            oAuth2Account = OAuth2Account.ofKakao(user, registrationId, attributeName);
//        }
        return oAuth2Account;
    }

    public static OAuth2Account ofKakao(OAuth2User user, String registrationId, String attributeName) {
        // user: kakao 에서 내려온 사용자 정보
        Map<String, Object> attributes = user.getAttributes();

        Map<String, Object> profile = (Map<String, Object>) attributes.get("properties");
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");

        String nickname = Optional.ofNullable((String) profile.get("nickname")).orElse("");
        String email = Optional.ofNullable((String) account.get("email")).orElse("");

        return OAuth2Account.builder()
                .providerName("KAKAO")
                .accountId(((Long) Objects.requireNonNull(user.getAttribute(attributeName))).toString())
                .email(email)
                .nickname(nickname)
                .build();
    }

    public void setMember(Member member) {
        this.member = member;
    }
}
