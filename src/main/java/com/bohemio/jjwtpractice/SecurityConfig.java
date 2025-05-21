package com.bohemio.jjwtpractice;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    public SecurityConfig(JwtTokenProvider jwtTokenProvider, CustomAccessDeniedHandler customAccessDeniedHandler, CustomAuthenticationEntryPoint customAuthenticationEntryPoint) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // ... (CSRF, 세션 관리 등 기존 설정들 - JWT는 보통 세션 사용 안 함) ...
                .sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS))// 세션 사용 안 함!
                .csrf(AbstractHttpConfigurer::disable) // CSRF 보호 비활성화 (Stateless 서버는 보통 비활성화)
                // ... (authorizeHttpRequests 설정) ...
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/authenticate", "/api/signup").permitAll() // 로그인, 회원가입 경로는 모두 허용
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )

                .exceptionHandling(exceptions -> exceptions
                                .authenticationEntryPoint(customAuthenticationEntryPoint)
                                .accessDeniedHandler(customAccessDeniedHandler)
                        )

                .formLogin(AbstractHttpConfigurer::disable)
                // 우리가 만든 JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 앞에 추가!
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 허용할 출처 (프론트엔드 개발 서버, 실제 배포 도메인 등)
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "https://naver.com"));
        // 허용할 HTTP 메소드
        configuration.setAllowedMethods( List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        // 허용할 HTTP 헤더 (모든 헤더를 허용하려면 "*")
        configuration.setAllowedHeaders(List.of("*"));
        // 브라우저에게 노출할 응답 헤더 (예: 커스텀 헤더, JWT 토큰 헤더 등)
        // configuration.setExposedHeaders(List.of("X-Custom-Header", "Authorization-Refresh"));
        // 자격 증명(쿠키, 인증 헤더 등)을 허용할지 여부
        configuration.setAllowCredentials(true); // true로 설정하면 allowedOrigins에 "*" 사용 불가
        // 예비 요청(Preflight) 결과 캐시 시간 (초 단위)
        configuration.setMaxAge(3600L); // 1시간

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // 모든 경로 ("/**")에 대해 위 설정 적용
        return source;
    }

}


