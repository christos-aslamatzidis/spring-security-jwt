package com.example.jwt.scheduler;

import com.example.jwt.repository.user.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Date;

@Service
@Transactional
@RequiredArgsConstructor
public class ExpiredTokenPurgeTask {
    private final TokenRepository tokenRepository;

    @Scheduled(cron = "${purge.cron.expression}")
    public void purgeExpired() {
        Date now = Date.from(Instant.now());
        tokenRepository.deleteByExpirationDateLessThan(now);
    }
}
