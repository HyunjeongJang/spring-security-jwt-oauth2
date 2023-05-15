package com.web.security.endpoint.jwtauth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ReIssueTokenRequest {
    private String refreshToken;
}
