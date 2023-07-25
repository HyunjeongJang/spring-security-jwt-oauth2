package com.web.security.endpoint.member.dto;

import com.web.security.domain.entity.Member;
import com.web.security.domain.type.MemberRole;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MemberResponse {

    private long memberId;
    private String email;
    private String password;
    private String nickname;
    private MemberRole role;

    public static MemberResponse from(Member member) {
        return new MemberResponse(
                member.getId(),
                member.getEmail(),
                member.getPassword(),
                member.getNickname(),
                member.getRole());
    }

}
