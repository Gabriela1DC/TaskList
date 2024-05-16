package com.gabriela_dc.tasklist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.gabriela_dc.tasklist.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException{

        var servletPath = request.getServletPath();
        if(servletPath.startsWith("/tasks/")){

            //Get auth (User + Password)
            var authorization = request.getHeader("Authorization");

            var authEncode = authorization.substring("Baisc".length()).trim();

            byte[] authDecode = Base64.getDecoder().decode(authEncode);
            var authString = new String(authDecode);
            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            // User validation
            var user = this.userRepository.findByUsername(username);
          if(user == null){
              response.sendError(401, "User without authorization");
          }else{

            // Password validation
            var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

            if(passwordVerify.verified){
                request.setAttribute("idUser", user.getId());
                filterChain.doFilter(request, response);
            }else{
                response.sendError(401, "User without authorization");
            }
//
//            //Continue the flow
//
            }
        }else{
            filterChain.doFilter(request, response);
        }


    }

}

