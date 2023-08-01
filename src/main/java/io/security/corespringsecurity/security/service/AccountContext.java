package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class AccountContext extends User {
    //DB 연동 처리시 반환 타입이 UserDetails type 이어야 함으로 설정.
    private final Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(),account.getPassword(), authorities);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
