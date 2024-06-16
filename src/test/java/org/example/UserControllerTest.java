package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.api.request.CreateUserReq;
import org.example.entity.User;
import org.example.entity.UserRole;
import org.example.repository.UserRepository;
import org.example.util.UserTestDataFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class UserControllerTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserTestDataFactory userTestDataFactory;

    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();
    @BeforeEach
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext)
          .apply(springSecurity())
          .build();
    }

    @Test
    public void testUserEndpoint() throws Exception {
        mockMvc.perform(get("/api/users")).andExpect(status().isOk());
    }

    @Test
    public void testMemberUserEndpoint() throws Exception {
        mockMvc.perform(get("/api/users/mem")).andExpect(status().isUnauthorized());
    }

    @Test
    public void testUser_NotAuthenticate_ReturnError() throws Exception {
        final String username = "tester";
        mockMvc.perform(get(String.format("/api/users/%s", username)).accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isUnauthorized());
    }

    @WithMockUser("tester")
    @Test
    public void testUserRole_FindSameUserName_Success() throws Exception {
        // Prepare data
        final String username = "tester";
        userTestDataFactory.createUser(username, "Tester", Collections.emptyList());

        mockMvc.perform(get(String.format("/api/users/%s", username)).accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.username").value(username));
    }

    @WithMockUser("tester")
    @Test
    public void testUserRole_FindAnotherUserName_ReturnError() throws Exception {
        // Prepare data
        final String otherUsername = "testerAnother";
        userTestDataFactory.createUser(otherUsername, "Tester", Collections.emptyList());

        mockMvc.perform(get(String.format("/api/users/%s", otherUsername)).accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isForbidden());
    }

    @WithMockUser(username = "mod", roles = {"MOD"})
    @Test
    public void testModRole_FindSameUserName_Success() throws Exception {
        // Prepare data
        final String username = "tester";
        userTestDataFactory.createUser(username, "Tester", Collections.emptyList());

        mockMvc.perform(get(String.format("/api/users/%s", username)).accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.username").value(username));
    }

    @Test
    public void testCreateUserSuccessful() throws Exception {
        final String username = "tester";
        CreateUserReq input = new CreateUserReq("tester@gmail.com", username, "xyz789", "xyz789",
          "Long", "Tran", "District 2", "Thu Duc", "+8412345678");
        mockMvc.perform(post("/api/users").content(objectMapper.writeValueAsString(input))
            .contentType(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isCreated())
          .andExpect(jsonPath("$.message").value("Create user successfully"))
          .andExpect(jsonPath("$.token").exists())
          .andExpect(jsonPath("$.token").isNotEmpty());

        // assert user
        Optional<User> optionalUser = userRepository.findByUsername(username);
        assertThat(optionalUser).isPresent();
        User user = optionalUser.get();
        assertThat(user.getUsername()).isEqualTo(username);
        assertThat(user.getAuthorities()).isNotEmpty().hasSize(1);
        assertThat(user.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsOnly(UserRole.USER.getAuthority());
    }

    @Test
    public void testCreateUserDuplicate_returnError() throws Exception {
        // Prepare data
        final String username = "tester";
        userTestDataFactory.createUser(username, "Tester", Collections.emptyList());

        CreateUserReq input = new CreateUserReq("tester@gmail.com", username,"xyz789", "xyz789",
          "Tester", "User", "District 1", "HCM", "+8412345678");
        mockMvc.perform(post("/api/users").content(objectMapper.writeValueAsString(input))
            .contentType(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isUnprocessableEntity())
          .andExpect(jsonPath("$.message").value("The username already existed"))
          .andExpect(jsonPath("$.token").doesNotExist());
    }

}
