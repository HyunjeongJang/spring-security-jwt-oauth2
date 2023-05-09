package com.web.security.domain.service;

import com.web.security.common.helper.JwtHelper;
import com.web.security.domain.repository.RefreshTokenRedisRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;

import static java.time.temporal.ChronoUnit.*;

@Service
@RequiredArgsConstructor
public class RefreshTokenRedisService {

    private final RefreshTokenRedisRepository refreshTokenRedisRepository;

    private final JwtHelper jwtHelper;

    public void save(String refreshToken) {
        String memberId = jwtHelper.extractSubject(refreshToken);
        long expiredAt = jwtHelper.extractExpiredAt(refreshToken);
        refreshTokenRedisRepository.save(memberId, refreshToken, Duration.of(expiredAt, SECONDS));

    }
}
