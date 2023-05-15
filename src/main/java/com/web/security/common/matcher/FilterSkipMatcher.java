package com.web.security.common.matcher;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

public class FilterSkipMatcher implements RequestMatcher {

    private final OrRequestMatcher matcher;

    public FilterSkipMatcher(List<String> skipPaths) {
        this.matcher = new OrRequestMatcher(skipPaths.stream()
                .map(AntPathRequestMatcher::new)
                .collect(Collectors.toList()));
    }

    @Override
    public boolean matches(HttpServletRequest request) { // 요청이 왔을 때 skipPaths 에 해당되는게 있는지 없는지 판단해서 boolean 내려주고 필터를 타게 할지말지 판단
        return !matcher.matches(request);
    }

}
