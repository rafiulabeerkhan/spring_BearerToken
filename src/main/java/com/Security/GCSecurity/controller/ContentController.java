package com.Security.GCSecurity.controller;

import com.Security.GCSecurity.model.MyUserDetailsService;
import com.Security.GCSecurity.webToken.JwtService;
import com.Security.GCSecurity.webToken.LoginForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContentController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private MyUserDetailsService myUserDetailsService;


    @GetMapping("/home")
    public String handleWelcome(){
        return "Home";
    }
    @GetMapping("/admin/home")
    public String handleAdminHome(){
        return "admin_home";
    }
    @GetMapping("/user/home")
    public String handleUserHome(){
        return "user_home";
    }

//    @GetMapping("/login")
//    public String handlelogin(){
//        return "custom_login";
//    }

    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody LoginForm loginForm){
   Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
           loginForm.username(), loginForm.password()
   ));
   if (authentication.isAuthenticated()){
      return jwtService.generateToken(myUserDetailsService.loadUserByUsername(loginForm.username()));
   }else{
       throw new UsernameNotFoundException("Invalid Credentials");
   }
    }
}
