package com.web.security.domain.repository;

import com.web.security.domain.entity.OAuth2Account;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuth2AccountRepository extends CrudRepository<OAuth2Account, Long> {
    boolean existsByProviderNameAndAccountId(String providerName, String accountId);

    OAuth2Account findByProviderNameAndAccountId(String providerName, String accountId);
}
