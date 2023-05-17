package com.web.security.domain.entity;

import com.web.security.domain.type.MemberRole;
import com.web.security.endpoint.member.dto.RegisterRequest;
import lombok.*;
import org.springframework.data.domain.AbstractAggregateRoot;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.*;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Getter
public class Member extends AbstractAggregateRoot {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    private String email;

    private String password;

    private String nickname;

    @Enumerated(EnumType.STRING)
    private MemberRole role;

    @Column(name = "enabled_yn")
    private boolean enabled;

    public static Member of(RegisterRequest request) {
        return Member.builder()
                .email(request.getEmail())
                .password(request.getPassword())
                .nickname(request.getNickname())
                .role(MemberRole.GENERAL)
                .enabled(!request.getPassword().isBlank())
                .build();
    }

    public boolean validatePassword(PasswordEncoder passwordEncoder, String password) {
        return passwordEncoder.matches(password, this.password);
    }



}
