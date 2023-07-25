package com.web.security.domain.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class BlackListRedisRepository {

    private final static String BLACKLIST_REDIS_KEY = "BLACK_LIST";
    private final RedisTemplate<String, String> redisTemplate;

    public void set(String accessToken) {
        redisTemplate.opsForHash().put(BLACKLIST_REDIS_KEY, accessToken, "accessToken");
    }

    public boolean exists(String accessToken) {
        return redisTemplate.opsForHash().get(BLACKLIST_REDIS_KEY, accessToken) != null;
    }

}
