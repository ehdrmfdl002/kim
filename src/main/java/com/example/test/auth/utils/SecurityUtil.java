package com.example.test.auth.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

public class SecurityUtil {

    /**
     * 현재 세션의 유저 인증 객체 호출 메소드
     * service 로직에서 토큰에서 가져온 userId가 아닌 인증객체에 존재하는 userId로
     * 비즈니스 로직 실행
     * JWT 토큰은 사용자 세션 관리용이지 인증용 X
     * 사용자의 정보는 인증객체 (Authentication)에서 가져와서 사용
     */
    public static Authentication getCurrentAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /**
     * 사용자 정보인 userId를 가져오는 메소드를 구분해서 생성
     * Override하여 사용하는 메소드들도 있어 인증객체를 파라미터로 받는 메소드와
     * SecurityUtil에서 호출해서 사용하는 메소드로 구분
     */
    public static String extractUsername() {
        Authentication authentication = getCurrentAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return userDetails.getUsername();
    }

    public static String extractUsername(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return userDetails.getUsername();
    }
}
