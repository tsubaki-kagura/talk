package org.kagura.runner;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class FilterDetailsRunner implements CommandLineRunner {
    private final FilterChainProxy filterChainProxy;

    @Override
    public void run(String @NonNull ... args) {
        filterChainProxy.getFilterChains()
                .forEach(filterChain -> {
                    String filters = filterChain.getFilters()
                            .stream()
                            .map(filter -> filter.getClass().getSimpleName())
                            .collect(Collectors.joining(","));
                    log.debug("Filter chain: {}", filters);
                });
    }
}
