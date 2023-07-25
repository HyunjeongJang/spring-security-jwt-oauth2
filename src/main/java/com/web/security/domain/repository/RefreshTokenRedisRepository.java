package com.web.security.domain.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class RefreshTokenRedisRepository {

    private final RedisTemplate<String, String> redisTemplate;

    private static final String KEY_PREFIX = "REFRESH_TOKEN:";

    public void save(String key, String value, Duration timeout) {
        redisTemplate.opsForValue().set(KEY_PREFIX + key, value, timeout);
    }

    public Optional<String> find(String key) {
        return Optional.ofNullable(redisTemplate.opsForValue().get(KEY_PREFIX + key));
    }

    public void delete(String key) {
        redisTemplate.opsForValue().getAndDelete(KEY_PREFIX + key);
    }

}
