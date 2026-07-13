package org.kagura.controller;

import lombok.RequiredArgsConstructor;
import org.kagura.domain.request.UnamePasswdRegisterRequest;
import org.kagura.result.Result;
import org.kagura.service.UserService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;

    @PostMapping("/code")
    public Result<Void> code() {
        return Result.ok("");
    }

    @PostMapping("/register")
    public Result<Void> register(@RequestBody UnamePasswdRegisterRequest registerDTO) {
        String passwd = registerDTO.passwd();
        if (!passwd.equals(registerDTO.passwd2())) {
            return Result.bad("前后两次密码不一致");
        }
        String uname = userService.register(registerDTO.uname(), passwd);
        return Result.ok("用户 " + uname + " 注册成功");
    }
}
