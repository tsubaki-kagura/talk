package org.kagura.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.http.HttpStatus;

/**
 * 统一响应实体
 *
 * @param code 状态码
 * @param message 响应消息
 * @param data 响应数据
 * @param timestamp 毫秒时间戳
 * @param <T> 响应数据类型，Void 表示无响应数据
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Result<T>(Integer code, String message, T data, Long timestamp) {
    private Result(HttpStatus status, String message, T data) {
        this(status.value(), message, data, System.currentTimeMillis());
    }

    private Result(HttpStatus status, String message) {
        this(status, message, null);
    }

    public static <T> Result<T> ok(T data) {
        return new Result<>(HttpStatus.OK, HttpStatus.OK.getReasonPhrase(), data);
    }

    public static <T> Result<T> ok(String message) {
        return new Result<>(HttpStatus.OK, message, null);
    }

    public static <T> Result<T> bad(String message) {
        return new Result<>(HttpStatus.BAD_REQUEST, message, null);
    }

    public static Result<Void> unauthorized(String message) {
        return new Result<>(HttpStatus.UNAUTHORIZED, message);
    }

    public static Result<Void> forbidden(String message) {
        return new Result<>(HttpStatus.FORBIDDEN, message);
    }
}
