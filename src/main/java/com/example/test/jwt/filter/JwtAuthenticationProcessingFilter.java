package com.example.test.jwt.filter;

import com.example.test.api.entity.RefreshToken;
import com.example.test.api.entity.User;
import com.example.test.api.repository.RefreshTokenMapper;
import com.example.test.api.repository.UserMapper;
import com.example.test.jwt.service.JwtService;
import com.example.test.utils.PasswordUtil;
import com.example.test.utils.error.CustomException;
import com.example.test.utils.error.ErrorCode;
import com.example.test.utils.error.ErrorResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * Jwt 인증 필터
 * "/login" 이외의 URI 요청이 왔을 때 처리하는 필터
 * <p>
 * 기본적으로 사용자는 요청 헤더에 AccessToken만 담아서 요청
 * AccessToken 만료 시에만 RefreshToken을 요청 헤더에 AccessToken과 함께 요청
 * <p>
 * 1. RefreshToken이 없고, AccessToken이 유효한 경우 -> 인증 성공 처리, RefreshToken을 재발급하지는 않는다.
 * 2. RefreshToken이 없고, AccessToken이 없거나 유효하지 않은 경우 -> 인증 실패 처리, 403 ERROR
 * 3. RefreshToken이 있는 경우 -> DB의 RefreshToken과 비교하여 일치하면 AccessToken 재발급, RefreshToken 재발급(RTR 방식)
 * 인증 성공 처리는 하지 않고 실패 처리
 */
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserMapper userMapper;
    private final RefreshTokenMapper refreshTokenMapper;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
    private static final String[] NO_CHECK_URLS = {"/auth", "/login"};
    @Value("${jwt.access.header}")
    private String accessHeader;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            log.info("필터 시작");
            log.info("Access Token 헤더에서 조회");

            String domain = request.getRequestURI();
            log.info("현재 도메인 {}", domain);

            //필터 제외 url 체크
            for (int i = 0; i < NO_CHECK_URLS.length; i++) {
                if (request.getRequestURI().startsWith(NO_CHECK_URLS[i])) {
                    filterChain.doFilter(request, response); // "/login" 요청이 들어오면, 다음 필터 호출
                    log.info("필터 제외 url {}", NO_CHECK_URLS[i]);
                    return;
                }
            }

            log.info("log : {}", request.getHeader(accessHeader));
            System.out.println("1 : " + jwtService.extractAccessToken(request));

            String accessToken = jwtService.extractAccessToken(request)
                    .filter(jwtService::isTokenValid)
                    .orElseThrow(() -> new CustomException(ErrorCode.TOKEN_NOT_VALID));

            String userId = jwtService.getUserId(accessToken);

            if (accessToken != null) {
                log.info("필터에서 Access Token 사용");
                checkAccessTokenAndAuthentication(request, response, filterChain);
                return;
            }

            if (accessToken == null) {
                log.info("필터에서 Refresh Token 사용");
                checkRefreshTokenAndReIssueAccessToken(response, userId);
            }
        } catch (CustomException e) {
            ErrorResponse errorResponse = new ErrorResponse(e.getErrorCode());
            response.setStatus(errorResponse.getStatus());
            response.setContentType("application/json;charset=UTF-8"); // JSON 응답 설정
            String jsonResponse = "{\n" +
                    "  \"status\": " + errorResponse.getStatus() + ",\n" +
                    "  \"code\": \"" + errorResponse.getCode() + "\",\n" +
                    "  \"message\": \"" + errorResponse.getMessage() + "\"\n" +
                    "}";
            response.getWriter().write(jsonResponse);
        }
    }

    /**
     * [액세스 토큰 체크 & 인증 처리 메소드]
     * request에서 extractAccessToken()으로 액세스 토큰 추출 후, isTokenValid()로 유효한 토큰인지 검증
     * 유효한 토큰이면, 액세스 토큰에서 extractId로 kakaoId을 추출한 후 findByKakaoId()로 해당 아이디를 사용하는 유저 객체 반환
     * 그 유저 객체를 saveAuthentication()으로 인증 처리하여
     * 인증 허가 처리된 객체를 SecurityContextHolder에 담기
     * 그 후 다음 인증 필터로 진행
     */
    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                  FilterChain filterChain) throws ServletException, IOException {
        log.info("checkAccessTokenAndAuthentication() 호출");
        jwtService.extractAccessToken(request)
                .filter(jwtService::isTokenValid)
                .ifPresent(accessToken -> jwtService.extractId(accessToken)
                        .ifPresent(id -> userMapper.selectUserById(id)
                                .ifPresent(this::saveAuthentication)));

        filterChain.doFilter(request, response);
    }

    /**
     * [리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드]
     * jwtService.createRefreshToken()으로 리프레시 토큰 재발급 후
     * DB에 재발급한 리프레시 토큰 업데이트 후 Flush
     */
    private String reIssueRefreshToken(User user) {
        String reIssuedRefreshToken = jwtService.createRefreshToken();
        Optional<RefreshToken> refreshToken = refreshTokenMapper.selectRefreshTokenById(user.getId());
        RefreshToken newRefreshToken = refreshToken.orElseThrow(() -> new IllegalStateException("DB에 refresh 토큰 없음"));
        refreshTokenMapper.update(user.getId(), reIssuedRefreshToken);

        return reIssuedRefreshToken;
    }

    public void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String id) {
        log.info("Refresh Token DB에서 조회");
        refreshTokenMapper.selectRefreshTokenById(id)
                .ifPresent(memberId -> {
                    Optional<User> user = userMapper.selectUserById((memberId.getId()));
                    User newUser = user.orElseThrow(() -> new IllegalStateException("member 불일치"));
                    reIssueRefreshToken(newUser);
                    jwtService.sendAccessToken(response, jwtService.createAccessToken(newUser.getId()));
                });
    }


    /**
     * [인증 허가 메소드]
     * 파라미터의 유저 : 우리가 만든 회원 객체 / 빌더의 유저 : UserDetails의 User 객체
     * <p>
     * new UsernamePasswordAuthenticationToken()로 인증 객체인 Authentication 객체 생성
     * UsernamePasswordAuthenticationToken의 파라미터
     * 1. 위에서 만든 UserDetailsUser 객체 (유저 정보)
     * 2. credential(보통 비밀번호로, 인증 시에는 보통 null로 제거)
     * 3. Collection < ? extends GrantedAuthority>로,
     * UserDetails의 User 객체 안에 Set<GrantedAuthority> authorities이 있어서 getter로 호출한 후에,
     * new NullAuthoritiesMapper()로 GrantedAuthoritiesMapper 객체를 생성하고 mapAuthorities()에 담기
     * <p>
     * SecurityContextHolder.getContext()로 SecurityContext를 꺼낸 후,
     * setAuthentication()을 이용하여 위에서 만든 Authentication 객체에 대한 인증 허가 처리
     */
    public void saveAuthentication(User myUser) {
        String password = myUser.getPassword();
        if (password == null) { // 소셜 로그인 유저의 비밀번호 임의로 설정 하여 소셜 로그인 유저도 인증 되도록 설정
            password = PasswordUtil.generateRandomPassword();
        }

        UserDetails userDetailsUser = org.springframework.security.core.userdetails.User.builder()
                .username(myUser.getId())
                .password(password)
                .roles(myUser.getRole().name())
                .build();

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(userDetailsUser, null,
                        authoritiesMapper.mapAuthorities(userDetailsUser.getAuthorities()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
