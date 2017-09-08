package com.mail.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class WelcomeController {

    @RequestMapping(value="/a", method = RequestMethod.GET)
    String index(){
    	System.out.println("...............hit");
        return "welcome";
    }

}