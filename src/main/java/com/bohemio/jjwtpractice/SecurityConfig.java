package com.bohemio.jjwtpractice;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;

    public SecurityConfig(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
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
                .formLogin(AbstractHttpConfigurer::disable)
                // 우리가 만든 JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 앞에 추가!
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ... (PasswordEncoder Bean 등) ...
}


