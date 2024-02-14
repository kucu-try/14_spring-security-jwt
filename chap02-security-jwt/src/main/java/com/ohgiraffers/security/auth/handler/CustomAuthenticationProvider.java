package com.ohgiraffers.security.auth.handler;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.auth.service.DetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private DetailsService detailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 1. username password token(사용자가 로그인 요청시 날린 아이디와 비밀번호를 가지고 있는 임시 객체)
        UsernamePasswordAuthenticationToken loginToken = (UsernamePasswordAuthenticationToken) authentication;
        String username = loginToken.getName();
        String password = (String) loginToken.getCredentials();

        // 2. DB에서 username에 해당하는 정보를 조회한다.
        DetailsUser foundUser = (DetailsUser) detailsService.loadUserByUsername(username);

        // 사용자가 입력한 username, password와 아이디의 비밀번호를 비교하는 로직을 수행함
        if (!passwordEncoder.matches(password, foundUser.getPassword())){
            throw new BadCredentialsException("password가 일치하지 않습니다");
        }

        return new UsernamePasswordAuthenticationToken(foundUser.getUsername(), foundUser.getPassword(), foundUser.getAuthorities());


    }

    @Override
    public boolean supports(Class<?> authentication) {

        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
