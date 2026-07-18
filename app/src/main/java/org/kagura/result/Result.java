package org.kagura.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.http.HttpStatus;

/**
 * 统一 API 响应体，包含状态码、消息、数据和时间戳。
 * 通过静态工厂方法创建常见响应，{@link JsonInclude} 确保为 {@code null} 的字段不出现在序列化结果中。
 *
 * @param <T> 数据类型
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

    public static Result<Void> unauthorized(String message) {
        return new Result<>(HttpStatus.UNAUTHORIZED, message);
    }

    public static Result<Void> forbidden(String message) {
        return new Result<>(HttpStatus.FORBIDDEN, message);
    }
}
