package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthenticationTest {


    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void testAuthEndpoint_NoPayload_Error() throws Exception {
        mockMvc.perform(post("/api/auth"))
          .andExpect(status().isUnauthorized());
    }

    @Test
    public void testAuthEndpoint_WrongPayload_Error() throws Exception {
        Map<String, String> payload = Map.of("username", "longthtran", "password", "The Thanos");
        mockMvc.perform(post("/api/auth").content(objectMapper.writeValueAsString(payload))
          .contentType(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isUnauthorized());
    }

}
