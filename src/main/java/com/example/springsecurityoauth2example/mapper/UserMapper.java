package com.example.springsecurityoauth2example.mapper;

import com.example.springsecurityoauth2example.entity.User;
import com.example.springsecurityoauth2example.model.request.CreateUserRequest;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(target = "id", ignore = true)
    User mapToUser(CreateUserRequest request);
}
