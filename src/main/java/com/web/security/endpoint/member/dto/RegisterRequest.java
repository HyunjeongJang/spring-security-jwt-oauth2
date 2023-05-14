package com.web.security.endpoint.member.dto;

import com.web.security.domain.entity.OAuth2Account;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    private String email;
    private String password;
    private String nickname;

    public static RegisterRequest from(OAuth2Account account) {
        return new RegisterRequest(account.getEmail(), "", account.getNickname());
    }
}
