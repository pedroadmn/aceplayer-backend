package com.pedroadmn.aceplayerbackend.controllers;

import org.junit.Before;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.testcontainers.containers.PostgreSQLContainer;


@SpringBootTest
@AutoConfigureMockMvc
class StatusControllerIntegrationTests {
    private static final String STATUS_ENDPOINT = "/status";

    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(
            "postgres:16.0-alpine3.18"
    );

    @Autowired
    private MockMvc mockMvc;

    @BeforeAll
    static void beforeAll() {
        postgres.start();
    }

    @AfterAll
    static void afterAll() {
        postgres.stop();
    }

    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.standaloneSetup(StatusController.class).build();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Test
    void shouldReturnStatusResponse() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .get(STATUS_ENDPOINT)
                        .accept("application/json")
                        .contentType("application/json"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("key").exists())
                .andExpect(MockMvcResultMatchers.jsonPath("key").value("status response"));
    }
}
