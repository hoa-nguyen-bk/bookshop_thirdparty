package com.cybersoft.thirdparty.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/3rd")
public class ThirdPartyController {
    @GetMapping
    public String index(){
        return "Hello from third party service";
    }
}
