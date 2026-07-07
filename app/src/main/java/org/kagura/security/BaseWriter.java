package org.kagura.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.kagura.result.Result;
import org.springframework.http.MediaType;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * 基础响应写入，用于向响应中写入数据
 */
@Slf4j
@Getter
@RequiredArgsConstructor
public abstract class BaseWriter {
    protected final JsonMapper jsonMapper;

    /**
     * 向响应中写入数据
     *
     * @param response 响应
     * @param result 待写入数据
     * @param <T> 数据类型
     */
    protected <T> void write(HttpServletResponse response, Result<T> result) {
        response.setCharacterEncoding(StandardCharsets.UTF_8);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        try (PrintWriter writer = response.getWriter()) {
            writer.write(jsonMapper.writeValueAsString(result));
        } catch (IOException exception) {
            log.error("响应数据写入失败..., result: {}", result, exception);
        }
    }
}
