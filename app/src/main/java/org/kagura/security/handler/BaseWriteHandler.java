package org.kagura.security.handler;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.kagura.result.Result;
import org.springframework.http.MediaType;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 基础写入处理器，用于向响应中写入数据
 */
@Getter
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class BaseWriteHandler {
    protected final JsonMapper jsonMapper;

    /**
     * 向响应中写入数据
     * @param response 响应
     * @param result 待写入数据
     * @param <T> 响应数据类型
     * @throws IOException 异常
     */
    protected <T> void write(HttpServletResponse response, Result<T> result) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        String responseString = jsonMapper.writeValueAsString(result);
        response.getWriter().write(responseString);
    }
}
