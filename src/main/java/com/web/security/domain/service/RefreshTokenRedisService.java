package com.web.security.domain.service;

import com.web.security.common.helper.JwtHelper;
import com.web.security.domain.repository.RefreshTokenRedisRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Optional;

import static java.time.temporal.ChronoUnit.*;

@Service
@RequiredArgsConstructor
public class RefreshTokenRedisService {

    private final RefreshTokenRedisRepository refreshTokenRedisRepository;
    private final JwtHelper jwtHelper;

    public void save(String refreshToken) {
        String memberId = jwtHelper.extractSubject(refreshToken);
        long expiredAt = jwtHelper.extractExpiredAt(refreshToken);
        long currentAt = System.currentTimeMillis();
        refreshTokenRedisRepository.save(memberId, refreshToken, Duration.of(expiredAt - currentAt, SECONDS));
    }

    public Optional<String> find(long memberId) {
        return refreshTokenRedisRepository.find(String.valueOf(memberId));
    }

}
