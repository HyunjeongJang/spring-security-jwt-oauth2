package com.web.security.domain.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Table(name = "oauth2_account")
public class Oauth2Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "oauth2_account_id")
    private Long id;

    private String providerName;

    private String accountId;

    @JoinColumn(name = "member_id", referencedColumnName = "member_id")
    @ManyToOne(fetch = FetchType.LAZY)
    private Member member;


}
