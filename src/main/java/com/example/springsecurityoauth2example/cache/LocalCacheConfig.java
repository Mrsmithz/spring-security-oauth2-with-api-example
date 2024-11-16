package com.example.springsecurityoauth2example.cache;

import com.example.springsecurityoauth2example.constant.CacheConstant;
import lombok.RequiredArgsConstructor;
import org.ehcache.config.CacheConfiguration;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.ExpiryPolicyBuilder;
import org.ehcache.config.builders.ResourcePoolsBuilder;
import org.ehcache.config.units.MemoryUnit;
import org.ehcache.jsr107.Eh107Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.jcache.JCacheCacheManager;
import org.springframework.cache.jcache.JCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.spi.CachingProvider;
import java.time.Duration;

@EnableCaching
@Configuration
@RequiredArgsConstructor
public class LocalCacheConfig {

    @Value("${local-cache-ttl:365}")
    private final Long cacheTTL;

    @Bean
    public JCacheManagerFactoryBean jCacheManagerFactoryBean() {
        return new JCacheManagerFactoryBean();
    }

    @Bean(name = {"jcache"})
    public JCacheCacheManager ehCacheCacheManager() {
        JCacheCacheManager cacheManager = new JCacheCacheManager();
        cacheManager.setCacheManager(initCacheManager());
        return cacheManager;
    }

    private CacheManager initCacheManager() {
        CachingProvider cachingProvider = Caching.getCachingProvider();
        CacheManager cacheManager = cachingProvider.getCacheManager();
        cacheManager.createCache(CacheConstant.REGISTERED_CLIENT_CACHE_NAME, registeredClientCacheConfig());
        return cacheManager;
    }

    private javax.cache.configuration.Configuration<String, RegisteredClient> registeredClientCacheConfig() {
        CacheConfiguration<String, RegisteredClient> cacheConfig = CacheConfigurationBuilder.newCacheConfigurationBuilder(
                        String.class,
                        RegisteredClient.class,
                        ResourcePoolsBuilder.newResourcePoolsBuilder()
                                .offheap(10, MemoryUnit.MB)
                                .build())
                .withExpiry(ExpiryPolicyBuilder.timeToIdleExpiration(Duration.ofDays(cacheTTL)))
                .build();
        return Eh107Configuration.fromEhcacheCacheConfiguration(cacheConfig);
    }
}
