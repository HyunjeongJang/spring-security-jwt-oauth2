package com.web.security.domain.repository;

import com.web.security.domain.entity.Member;
import org.springframework.data.repository.CrudRepository;

public interface MemberRepository extends CrudRepository<Member, Long> {
}
