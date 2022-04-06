package com.rixrod.oboshiefashion.controllers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

    @Value("${app.url.confirm}")
    private String greeting;

    @Value("${spring.banner.location}")
    private String banner;

    @GetMapping(path = "/greeting")
    public String greet(){
        return banner;
    }
}
