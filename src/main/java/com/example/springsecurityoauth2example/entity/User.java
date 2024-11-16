package com.example.springsecurityoauth2example.entity;

import com.example.springsecurityoauth2example.constant.Role;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "users")
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class User {

    @Id
    @JsonIgnore
    private String id;

    @Indexed(unique = true)
    private String email;

    @Field("first_name")
    private String firstName;

    @Field("last_name")
    private String lastName;

    private Role role;
}
