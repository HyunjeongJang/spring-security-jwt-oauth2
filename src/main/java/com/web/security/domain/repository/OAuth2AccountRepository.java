package com.web.security.domain.repository;

import com.web.security.domain.entity.OAuth2Account;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface OAuth2AccountRepository extends CrudRepository<OAuth2Account, Long> {
    boolean existsByProviderNameAndAccountId(String providerName, String accountId);

    OAuth2Account findByProviderNameAndAccountId(String providerName, String accountId);

    @Modifying // Spring Data 의 규칙 -> 데이터가 수정되는 쿼리라는 걸 알려주는 용도
    @Transactional
    void deleteAllByMemberId(long memberId);
}
