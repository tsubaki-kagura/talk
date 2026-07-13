package org.kagura.domain.request;

/**
 * 进行验证码请求所需要提交的信息
 *
 * @param email 接收验证码的邮箱
 */
public record AuthCodeRequest(String email) {
}
