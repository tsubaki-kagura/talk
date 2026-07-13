package org.kagura.domain.request;

/**
 * 进行注册所需要提交的注册信息
 *
 * @param uname 用于注册的用户名
 * @param passwd 用于注册的密码
 * @param passwd2 用于注册的二次确认密码
 */
public record UnamePasswdRegisterRequest(String uname, String passwd, String passwd2) {
}
