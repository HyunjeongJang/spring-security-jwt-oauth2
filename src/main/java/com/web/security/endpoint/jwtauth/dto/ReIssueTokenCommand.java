package com.web.security.endpoint.jwtauth.dto;

import com.web.security.domain.type.MemberRole;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ReIssueTokenCommand {
    private long memberId;
    private MemberRole role;
    private String refreshToken;
}
