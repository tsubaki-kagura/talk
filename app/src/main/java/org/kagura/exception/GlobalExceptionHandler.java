package org.kagura.exception;

import org.kagura.result.Result;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BaseException.class)
    public Result<Void> onBaseException(BaseException exception) {
        return Result.ok(exception.getMessage());
    }
}
