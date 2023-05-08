package com.web.security.domain.entity;

import com.web.security.domain.type.MemberRole;
import com.web.security.endpoint.member.dto.RegisterRequest;
import lombok.*;

import javax.persistence.*;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Getter
public class Member {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    private String email;

    private String password;

    private String nickname;

    public static Member from(RegisterRequest req, String encryptedPassword) {
        return Member.builder()
                .email(req.getEmail())
                .password(encryptedPassword)
                .nickname(req.getNickname())
                .build();
    }



}
