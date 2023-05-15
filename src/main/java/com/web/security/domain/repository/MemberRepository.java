package com.web.security.domain.repository;

import com.web.security.domain.entity.Member;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository extends CrudRepository<Member, Long> {

    boolean existsByEmail(String email);

    Optional<Member> findByEmail(String email); // find~ 는 Optional 이 컨벤션

    Member getByEmail(String email); // get 으로 시작하는건 Optional 없는게 컨벤션
}
