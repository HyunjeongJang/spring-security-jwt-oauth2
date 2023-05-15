package com.web.security.endpoint.jwtauth.service;

import com.web.security.common.helper.JwtHelper;
import com.web.security.domain.service.RefreshTokenRedisService;
import com.web.security.endpoint.jwtauth.dto.ReIssueTokenCommand;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtAuthService {

    private final RefreshTokenRedisService refreshTokenRedisService;
    private final JwtHelper jwtHelper;

    public String reIssueAccessToken(ReIssueTokenCommand command) {
        String savedToken = refreshTokenRedisService.find(command.getMemberId())
                .orElseThrow(() -> new RuntimeException("해당 사용자의 RefreshToken 을 찾을 수 없습니다."));
        if (command.getRefreshToken().equals(savedToken)) {
            return jwtHelper.generateAccessToken(String.valueOf(command.getMemberId()), command.getRole().name());
        }
        throw new RuntimeException("RefreshToken 정보가 잘못되어 AccessToken 을 재발급할 수 없습니다.");
    }

}
