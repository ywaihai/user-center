package com.yupi.usercenter.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.yupi.usercenter.common.ErrorCode;
import com.yupi.usercenter.exception.BusinessException;
import com.yupi.usercenter.model.User;
import com.yupi.usercenter.service.UserService;
import com.yupi.usercenter.mapper.UserMapper;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.yupi.usercenter.contant.UserConstant.USER_LOGIN_STATE;

/**
 * @author waihai
 * @description 用户服务实现类
 * @createDate  2024-1-27
 */
@Slf4j
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User>
    implements UserService{
    /**
     * 盐值
     */
    private static final String SALT = "waihai";

    @Resource
    private UserMapper userMapper;

    @Override
    public long userRegister(String userAccount, String userPassword, String checkPassword, String planetCode) {
        // 1. 校验字符串是否为空
        if (StringUtils.isAnyBlank(userAccount, userPassword, checkPassword, planetCode)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        // 2. 校验用户账号长度
        if (userAccount.length() < 4) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        // 3. 校验密码长度
        if (userPassword.length() < 8 || checkPassword.length() < 8) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        // 4. 校验星球编号长度
        if (planetCode.length() > 5) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "星期编号过长");
        }
        // 4. 账户不能包含特殊字符
        String validPattern = "[`~!@#$%^&*()+=|{}':;',\\\\[\\\\].<>/?~！@#￥%……&*（）——+|{}【】‘；：”“’。，、？]";
        Matcher matcher = Pattern.compile(validPattern).matcher(userAccount);
        if (matcher.find()) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        // 5. 账号不能重复
        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("userAccount", userAccount);
        long count = userMapper.selectCount(queryWrapper);
        if (count > 0) {
            return -1;
        }
        // 5. 星球编号不能重复
        queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("planetCode", planetCode);
        count = userMapper.selectCount(queryWrapper);
        if (count > 0) {
            return -1;
        }
        // 6. 密码与校验密码相同
        if (!userPassword.equals(checkPassword)) {
            return -1;
        }
        // 7. 加密
        String encryptPassword = DigestUtils.md5DigestAsHex((SALT + userPassword).getBytes());
        // 8. 插入数据
        User user = new User();
        user.setUserAccount(userAccount);
        user.setUserPassword(encryptPassword);
        user.setPlanetCode(planetCode);
        boolean saveResult = this.save(user);
        if (!saveResult) {
            return -1;
        }
        return user.getId();
    }

    @Override
    public User userLogin(String userAccount, String userPassword, HttpServletRequest request) {
        // 1. 校验字符串是否为空
        if (StringUtils.isAnyBlank(userAccount, userPassword)) {
            return null;
        }
        // 2. 校验用户账号长度
        if (userAccount.length() < 4) {
            return null;
        }
        // 3. 校验密码长度
        if (userPassword.length() < 8) {
            return null;
        }
        // 4. 账户不能包含特殊字符
        String validPattern = "[`~!@#$%^&*()+=|{}':;',\\\\[\\\\].<>/?~！@#￥%……&*（）——+|{}【】‘；：”“’。，、？]";
        Matcher matcher = Pattern.compile(validPattern).matcher(userAccount);
        if (matcher.find()) {
            return null;
        }
        // 5. 加密
        String encryptPassword = DigestUtils.md5DigestAsHex((SALT + userPassword).getBytes());
        // 6. 校验密码是否输入正确
        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("userAccount", userAccount);
        queryWrapper.eq("userPassword", encryptPassword);
        User user = userMapper.selectOne(queryWrapper);
        //用户不存在
        if (user == null) {
            log.info("user login failed, userAccount cannot match userPassword");
            return null;
        }
        // 7. 脱敏
        User saftyUser = getSaftyUser(user);
        // 8. 记录用户的登录态
        request.getSession().setAttribute(USER_LOGIN_STATE, saftyUser);

        return saftyUser;
    }

    /**
     *用户脱敏
     *
     * @param orginUser 用户信息
     * @return
     */
    @Override
    public User getSaftyUser(User orginUser) {
        if (orginUser == null) {
            throw new BusinessException(ErrorCode.NOT_LOGIN, "用户未登录");
        }
        User saftyUser = new User();
        saftyUser.setId(orginUser.getId());
        saftyUser.setUsername(orginUser.getUsername());
        saftyUser.setUserAccount(orginUser.getUserAccount());
        saftyUser.setAvatarUrl(orginUser.getAvatarUrl());
        saftyUser.setGender(orginUser.getGender());
        saftyUser.setPhone(orginUser.getPhone());
        saftyUser.setEmail(orginUser.getEmail());
        saftyUser.setUserStatus(orginUser.getUserStatus());
        saftyUser.setCreateTime(orginUser.getCreateTime());
        saftyUser.setUserRole(orginUser.getUserRole());
        saftyUser.setPlanetCode(orginUser.getPlanetCode());

        return saftyUser;
    }

    /**
     * 用户注销
     *
     * @param request 请求
     * @return Integer对象
     */
    @Override
    public Integer userLogout(HttpServletRequest request) {
        //移除登录态
        request.getSession().removeAttribute(USER_LOGIN_STATE);
        return 1;
    }
}




