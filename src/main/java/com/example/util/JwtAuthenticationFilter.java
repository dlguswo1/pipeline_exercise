package com.example.util;


import com.example.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
@Slf4j
// jwt 인증, 권한 부여
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserService userService;

    @Value("${jwt.secretKey}")
    private final String secretKey;


    @Override
    protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response,
                                    jakarta.servlet.FilterChain filterChain) throws jakarta.servlet.ServletException, IOException {

        String head = "Bearer ";
        // 막는기능

        // 토큰을 꺼내기
        final String authorization = head + request.getHeader(HttpHeaders.AUTHORIZATION);
        log.info("authorization : {}", authorization);

        // 토큰이 없을 경우
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.error("authorization : is null or wrong");
            filterChain.doFilter(request, response);
            return;
        }



        // 토큰에서 이름 꺼내기
        String realToken = authorization.split(" ")[1];


        // 만료되었는지 여부
        if (JwtTokenizer.isExpired(realToken, secretKey)) {
            log.error("token is expired");
            filterChain.doFilter(request, response);
            return;
        }

        // userName 토큰에서 꺼내기
        String token = JwtTokenizer.getMemberId(realToken, secretKey);
        log.info("memberId : {}", token);

        // 권한 부여
        UsernamePasswordAuthenticationToken authenticationToken =
                // 나중에 db에서 role을 꺼내오자
                // 지금은 하드코딩으로 rile = user 넣어놨음
                new UsernamePasswordAuthenticationToken(token, null, List.of(new SimpleGrantedAuthority("USER")));
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request, response);

//        try {
//            token = getToken((HttpServletRequest) request);
//            if (StringUtils.hasText(token)) {
//                getAuthentication(token);
//            }
//            filterChain.doFilter(request, response);
//        }
//        catch (NullPointerException | IllegalStateException e) {
//            request.setAttribute("exception", JwtExceptionCode.NOT_FOUND_TOKEN.getCode());
//            log.error("Not found Token // token : {}", token);
//            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
//            throw new BadCredentialsException("throw new not found token exception");
//        } catch (SecurityException | MalformedJwtException e) {
//            request.setAttribute("exception", JwtExceptionCode.INVALID_TOKEN.getCode());
//            log.error("Invalid Token // token : {}", token);
//            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
//            throw new BadCredentialsException("throw new invalid token exception");
//        } catch (ExpiredJwtException e) {
//            request.setAttribute("exception", JwtExceptionCode.EXPIRED_TOKEN.getCode());
//            log.error("EXPIRED Token // token : {}", token);
//            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
//            throw new BadCredentialsException("throw new expired token exception");
//        } catch (UnsupportedJwtException e) {
//            request.setAttribute("exception", JwtExceptionCode.UNSUPPORTED_TOKEN.getCode());
//            log.error("Unsupported Token // token : {}", token);
//            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
//            throw new BadCredentialsException("throw new unsupported token exception");
//        } catch (Exception e) {
//            log.error("====================================================");
//            log.error("JwtFilter - doFilterInternal() 오류 발생");
//            log.error("token : {}", token);
//            log.error("Exception Message : {}", e.getMessage());
//            log.error("Exception StackTrace : {");
//            e.printStackTrace();
//            log.error("}");
//            log.error("====================================================");
//            throw new BadCredentialsException("throw new exception");
//        }
    }

//    private void getAuthentication(String token) {
//        JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(token);
//        // 토큰이 올바르면 인증정보를 받아옴
//        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
//        // 값을 담아줌
//        SecurityContextHolder.getContext()
//                .setAuthentication(authenticate);
//    }
//
//    private String getToken(HttpServletRequest request) {
//        String authorization = request.getHeader("Authorization");
//        if (StringUtils.hasText(authorization) && authorization.startsWith("Bearer")){
//            String[] arr = authorization.split(" ");
//            return arr[1];
//        }
//        return null;
//    }

}