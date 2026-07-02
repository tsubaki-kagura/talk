package org.kagura.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.http.HttpStatus;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record Result<T>(Integer code, String message, T data) {
    public static <T> Result<T> ok(T data) {
        return new Result<>(HttpStatus.OK.value(), HttpStatus.OK.getReasonPhrase(), data);
    }

    public static Result<Void> ok(String message) {
        return new Result<>(HttpStatus.OK.value(), message, null);
    }

    public static Result<Void> unauthorized(String message) {
        return new Result<>(HttpStatus.UNAUTHORIZED.value(), message, null);
    }

    public static Result<Void> forbidden(String message) {
        return new Result<>(HttpStatus.FORBIDDEN.value(), message, null);
    }
}
