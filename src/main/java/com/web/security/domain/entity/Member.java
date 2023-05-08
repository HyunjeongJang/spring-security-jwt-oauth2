package com.web.security.domain.entity;

import com.web.security.domain.type.MemberRole;
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

//    private MemberRole role;

//    @Column(name = "enabled_yn")
//    private boolean enabled;



}
