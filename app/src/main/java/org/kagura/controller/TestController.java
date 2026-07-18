package org.kagura.controller;

import org.kagura.result.Result;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    /**
     * 连通性测试接口
     *
     * @return 测试响应
     */
    @GetMapping("/test")
    public Result<String> test() {
        return Result.ok("Hello World");
    }
}
