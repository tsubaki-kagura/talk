package org.kagura.domain.request;

/**
 * 进行用户名密码认证所需要提交的认证信息
 *
 * @param uname 用于登录的用户名
 * @param passwd 用于登录的密码
 */
public record UnamePasswdLoginRequest(String uname, String passwd) {
}
