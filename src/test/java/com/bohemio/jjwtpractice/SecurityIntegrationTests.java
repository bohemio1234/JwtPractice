package com.bohemio.jjwtpractice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser; // 핵심!
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;


@SpringBootTest // Spring Boot 전체 컨텍스트 로드
@AutoConfigureMockMvc // MockMvc 자동 설정 및 주입
public class SecurityIntegrationTests {

    @Autowired
    private MockMvc mockMvc; // HTTP 요청 시뮬레이션 객체

    @Test
    void 비인증_사용자_유저API_접근시_401응답() throws Exception {
        mockMvc.perform(get("/api/user/my-info")) // /api/user/my-info 는 인증 필요하다고 가정
                .andExpect(status().isUnauthorized()); // 401 Unauthorized 예상!
    }

    @Test
    @WithMockUser(username = "testuser", roles = {"USER"}) // "USER" 역할을 가진 "testuser"로 로그인한 것처럼!
    void USER역할_사용자_유저API_접근시_200응답() throws Exception {
        mockMvc.perform(get("/api/user/my-info"))
                .andExpect(status().isOk()); // 200 OK 예상!
    }

    @Test
    @WithMockUser(username = "testuser", roles = {"GUEST"}) // "GUEST" 역할을 가진 사용자는 USER API 접근 불가하다고 가정
    void GUEST역할_사용자_유저API_접근시_403응답() throws Exception {
        mockMvc.perform(get("/api/user/my-info"))
                .andExpect(status().isForbidden()); // 403 Forbidden 예상!
    }

    @Test
    @WithMockUser(username = "adminuser", roles = {"ADMIN"})
    void ADMIN역할_사용자_어드민API_접근시_200응답() throws Exception {
        mockMvc.perform(get("/api/admin/some-data")) // /api/admin/some-data 는 ADMIN 역할 필요하다고 가정
                .andExpect(status().isOk());
    }
}