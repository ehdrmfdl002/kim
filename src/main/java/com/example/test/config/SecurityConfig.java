package com.example.test.config;


import com.example.test.api.repository.RefreshTokenMapper;
import com.example.test.api.repository.UserMapper;
import com.example.test.jwt.filter.JwtAuthenticationProcessingFilter;
import com.example.test.jwt.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * 인증은 CustomJsonUsernamePasswordAuthenticationFilter에서 authenticate()로 인증된 사용자로 처리
 * JwtAuthenticationProcessingFilter는 AccessToken, RefreshToken 재발급
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtService jwtService;
    private final UserMapper userMapper;
    private final RefreshTokenMapper refreshTokenMapper;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors();
        http
                .formLogin().disable() // FormLogin 사용 X
                .httpBasic().disable() // httpBasic 사용 X
                .csrf().disable() // csrf 보안 사용 X

                .headers()
                .frameOptions().sameOrigin()
                .cacheControl().disable() // 캐시 비활성화
                .and()

                // 세션 사용하지 않으므로 STATELESS로 설정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()

                //== URL별 권한 관리 옵션 ==//
                .authorizeRequests()
                .antMatchers("/ws/**", "/socket.io/**", "/auth/**", "/api/login/**", "/login/**", "/login", "/api/login")
//                .antMatchers( "/**")
                .permitAll()
                .anyRequest()
                .authenticated() // 위의 경로 이외에는 모두 인증된 사용자만 접근 가능

                .and();
                //ADJUST: filter를 Bean에 등록시키지 않고 시큐리티필터체인안에서 돌도록 변경함.
//                .addFilterBefore(new JwtAuthenticationProcessingFilter(jwtService, userMapper, refreshTokenMapper), UsernamePasswordAuthenticationFilter.class);
        //== 소셜 로그인 설정 ==//

        return http.build();
    }

    @Bean
    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() {
        JwtAuthenticationProcessingFilter jwtAuthenticationFilter = new JwtAuthenticationProcessingFilter(jwtService, userMapper, refreshTokenMapper);
        return jwtAuthenticationFilter;
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * AuthenticationManager 설정 후 등록
     * PasswordEncoder를 사용하는 AuthenticationProvider 지정 (PasswordEncoder는 위에서 등록한 PasswordEncoder 사용)
     * FormLogin(기존 스프링 시큐리티 로그인)과 동일하게 DaoAuthenticationProvider 사용
     * UserDetailsService는 커스텀 LoginService로 등록
     * 또한, FormLogin과 동일하게 AuthenticationManager로는 구현체인 ProviderManager 사용(return ProviderManager)
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(provider);
    }

    // ADJUST
    // 문제점: jwt인증하는 filter가 bean에 등록되어 있어서 무조건 filter를 돌게되어 있어서 security와 관계없이 default chain에서 동작하는 문제점 발생
    // 해결: Bean에 등록하는 것이 아닌 Security의 filterChain에 등록함으로써 해결
//    @Bean
//    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() {
//        JwtAuthenticationProcessingFilter jwtAuthenticationFilter = new JwtAuthenticationProcessingFilter(jwtService, userRepository);
//        return jwtAuthenticationFilter;
//    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true);
//        config.addAllowedOrigin("*");
        config.addAllowedOrigin("http://localhost:3000");
        config.addAllowedOrigin("http://localhost:8080");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.setMaxAge(3600L);
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    // ADJUST
    // WebSecurity가 Bean에 등록되지 않아 WebSecurity가 동작하지 않았음. 그래서 시큐리티의 antMatchers가 동작하지 않고
    // jwtFilter가 작동하는 문제점이 발생했음.
    // WebSecurity를 해결: Bean에 등록하면서 해결함.
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web
                .ignoring()
                .antMatchers(
                        "/swagger-ui/**",
                        "/v2/api-docs",
                        "/webjars/**",
                        "/swagger-resources/**",
                        "/swagger/**",
                        "/ws/**",
                        "/actuator/**",
                        "/auth/**"
                );
    }
}
