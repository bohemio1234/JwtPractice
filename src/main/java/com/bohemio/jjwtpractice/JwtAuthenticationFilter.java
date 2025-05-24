package com.bohemio.jjwtpractice;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }


    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        // "Bearer " 로 시작하는 토큰인지, 그리고 실제로 텍스트가 있는지 확인
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // "Bearer " 7글자 뒤부터가 진짜 토큰
        }
        return null; // 없으면 null 반환
    }


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {


        String token = resolveToken( request );

        // 토큰이 실제로 존재하고, 유효한 토큰인지 확인
        if (StringUtils.hasText( token ) && jwtTokenProvider.validateToken( token )) {
            // 토큰이 유효하니까, 토큰에서 인증 정보(Authentication 객체)를 꺼내기.
            Authentication authentication = jwtTokenProvider.getAuthentication( token );
            //꺼내온 인증 정보를 SecurityContextHolder에 저장. 이게 성공하면 사용자는 완벽히 성공적으로 인증됨.
            //물론 stateless라서 게속 실행됨.
            SecurityContextHolder.getContext().setAuthentication( authentication );
            logger.debug( "Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), request.getRequestURI() );
        } else {
            logger.debug( "유효한 JWT 토큰이 없습니다, uri: {}", request.getRequestURI() );
        }

        // 이 필터에서의 작업이 끝났으면 다음 필터에게 다음 작업들 처리하게 해 줘야함.
        filterChain.doFilter( request, response );

    }


}
