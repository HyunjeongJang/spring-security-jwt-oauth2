package com.web.security.domain.repository;

import com.web.security.domain.entity.Member;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MemberRepository extends CrudRepository<Member, Long> {

    boolean existsByEmail(String email);
}
