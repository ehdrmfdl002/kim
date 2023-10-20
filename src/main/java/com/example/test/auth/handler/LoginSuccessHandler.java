package com.example.test.auth.handler;

import com.example.test.api.entity.RefreshToken;
import com.example.test.api.repository.RefreshTokenMapper;
import com.example.test.api.repository.UserMapper;
import com.example.test.jwt.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final RefreshTokenMapper refreshTokenMapper;

    @Value("${jwt.access.expiration}")
    private String accessTokenExpiration;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        try {
            String id = extractUsername(authentication); // 인증 정보에서 Username(id) 추출
            System.out.println("Eid : " + id);

            String accessToken = jwtService.createAccessToken(id); // JwtService의 createAccessToken을 사용하여 AccessToken 발급
            String refreshToken = jwtService.createRefreshToken(); // JwtService의 createRefreshToken을 사용하여 RefreshToken 발급

            Optional<RefreshToken> currentRefreshToken = refreshTokenMapper.selectRefreshTokenById(id);
            if (currentRefreshToken.isPresent()) {
                RefreshToken newRefreshToken = currentRefreshToken.get();
                newRefreshToken.setRefreshToken(refreshToken);
                refreshTokenMapper.update(id, newRefreshToken.getRefreshToken());
            } else {
                refreshTokenMapper.save(id, refreshToken);
            }

            jwtService.sendAccessToken(response, accessToken);

            // TODO : 로그인 성공 시 리다이렉트 시키는 URL 변경
            String redirectUrl = "http://localhost:8080/main?token=" + accessToken;
            response.sendRedirect(redirectUrl);

            log.info("로그인에 성공하였습니다. 아이디 : {}", id);
            log.info("로그인에 성공하였습니다. AccessToken : {}", accessToken);
            log.info("발급된 AccessToken 만료 기간 : {}", accessTokenExpiration);
        } catch (Exception e) {
            log.info(e.getMessage());
        }

    }

    private String extractUsername(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return userDetails.getUsername();
    }
}
