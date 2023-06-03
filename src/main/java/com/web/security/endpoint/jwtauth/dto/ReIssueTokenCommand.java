package com.web.security.endpoint.jwtauth.dto;

import com.web.security.domain.type.MemberRole;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.Authentication;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ReIssueTokenCommand {
    // command : controller -> service(application service)

    private long memberId;
    private MemberRole role;
    private String refreshToken;

//    public ReIssueTokenCommand(Authentication auth, ReIssueTokenRequest request) {
//        this.memberId = (Long) auth.getPrincipal();
//        this.role = (MemberRole) auth.getAuthorities().stream().findFirst().get();
//        this.refreshToken = request.getRefreshToken();
//    }

}
