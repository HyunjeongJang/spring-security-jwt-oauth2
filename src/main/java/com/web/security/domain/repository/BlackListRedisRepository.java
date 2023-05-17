package com.web.security.domain.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class BlackListRedisRepository {

    // 어떤 자료구조로 데이터를 넣을것인가 -> List 에 넣었을 때 단점은 속도 -> Hash
    // 해당 데이터의 만료기간 -> AccessToken 의 만료기간
    private final static String BLACKLIST_REDIS_KEY = "BLACK_LIST";
    private final RedisTemplate<String, String> redisTemplate;

    public void set(String accessToken) {
        redisTemplate.opsForHash().put(BLACKLIST_REDIS_KEY, accessToken, "accessToken");
    }

    public boolean exists(String accessToken) {
        return redisTemplate.opsForHash().get(BLACKLIST_REDIS_KEY, accessToken) != null;
    }

}
