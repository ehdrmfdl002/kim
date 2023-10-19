package com.example.test.api.repository;

import com.example.test.api.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.util.Optional;

@Mapper
public interface UserMapper {
    @Select("SELECT id, password FROM `User` WHERE id = #{id}")
    Optional<User> selectUserById(String id);
}
