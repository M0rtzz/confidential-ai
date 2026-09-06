package org.secretflow.secretpad.web.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

class IndexControllerTest {
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new IndexController()).build();
    }

    @Test
    void confidentialComputeRouteLoadsSpaIndex() throws Exception {
        mockMvc.perform(get("/confidential-compute"))
                .andExpect(status().isOk())
                .andExpect(view().name("index"));
        mockMvc.perform(get("/confidential-compute/"))
                .andExpect(status().isOk())
                .andExpect(view().name("index"));
    }
}
