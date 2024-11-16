package com.example.springsecurityoauth2example.model.request;

import com.example.springsecurityoauth2example.constant.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserRequest {

    private String email;
    private String firstName;
    private String lastName;
    private Role role;
}
