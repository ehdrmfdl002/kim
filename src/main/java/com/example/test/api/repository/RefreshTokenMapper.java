package com.example.test.api.repository;

import com.example.test.api.entity.RefreshToken;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import java.util.Optional;

@Mapper
public interface RefreshTokenMapper {
    @Select("SELECT id, refreshToken FROM RefreshToken WHERE id = #{id}")
    Optional<RefreshToken> selectRefreshTokenById(String id);
    @Insert("insert into RefreshToken(id, refreshToken) values (#{id}, #{refreshToken});")
    void save(String id, String refreshToken);
    @Update("update RefreshToken set refreshToken = #{refreshToken} where id = #{id}")
    void update(String id, String refreshToken);
}
