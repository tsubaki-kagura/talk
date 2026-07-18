package org.kagura.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;

@Configuration
public class RedisConfig {

    /**
     * 创建 JSON 序列化的 RedisTemplate，Key 使用 String 序列化，Value 使用 JSON 序列化
     *
     * @param redisConnectionFactory Redis 连接工厂
     * @return JsonRedisTemplate 实例
     */
    @Bean
    public JsonRedisTemplate jsonRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        return new JsonRedisTemplate(redisConnectionFactory);
    }

    /**
     * 自定义 RedisTemplate，Key 使用 String 序列化，Value 使用 JSON 序列化，具体实现借鉴于 StringRedisTemplate
     */
    public static class JsonRedisTemplate extends RedisTemplate<String, Object> {
        private JsonRedisTemplate() {
            setKeySerializer(RedisSerializer.string());
            setValueSerializer(RedisSerializer.json());
            setHashKeySerializer(RedisSerializer.string());
            setHashValueSerializer(RedisSerializer.json());
        }

        private JsonRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
            this();
            setConnectionFactory(redisConnectionFactory);
            afterPropertiesSet();
        }
    }
}
