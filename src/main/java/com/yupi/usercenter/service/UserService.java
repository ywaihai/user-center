package com.yupi.usercenter.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.yupi.usercenter.model.User;
import jakarta.servlet.http.HttpServletRequest;

/**
* @author waihai
* @description 针对表【user(用户)】的数据库操作Service
* @createDate 2024-01-26 12:21:50
*/
public interface UserService extends IService<User> {
    /**
     *用户注册
     *
     * @param userAccount 用户账号
     * @param userPassword 用户密码
     * @param checkPassword 校验密码
     * @param planetCode 星球编号
     * @return 新用户id
     */
    long userRegister(String userAccount, String userPassword, String checkPassword, String planetCode);

    /**
     * 用户登录
     *
     * @param userAccount  用户账号
     * @param userPassword 用户密码
     * @param request      请求
     * @return 脱敏后的用户信息
     */
    User userLogin(String userAccount, String userPassword, HttpServletRequest request);

    /**
     * 用户脱敏
     *
     * @param user 用户信息
     * @return 脱敏后的用户信息
     */
    User getSaftyUser(User user);

    /**
     * 用户注销
     *
     * @param request 请求
     * @return Integer对象
     */
    Integer userLogout(HttpServletRequest request);

}
