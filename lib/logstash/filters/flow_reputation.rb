# frozen_string_literal: true

# logstash-filter-ti-reputation.rb

require 'dalli'
require 'logstash/filters/base'
require 'logstash/namespace'
require 'json'

require_relative 'utils/data_cache'
require_relative 'utils/memcached_config'

module LogStash
  module Filters
    class FlowReputation < LogStash::Filters::Base
      config_name 'flow_reputation'

      config :key_mapping, validate: :hash, default: {}
      config :memcached_servers, validate: :array, default: ["memcached.service:11211"]
      config :memcached_namespace, validate: :string, default: "rbflowrep"
      config :sensor_field, validate: :string, default: "sensor_name"
      config :sensor_policy_map, validate: :hash, required: true

      def register
        begin
          @memcached_manager = MemcachedManager.new(@memcached_servers)
        rescue => e
          @logger.error("Error initializing Memcached client: #{e.message}")
          @logger.debug("Backtrace: #{e.backtrace.join("\n")}")
          @memcached_manager = nil
        end
      end

      def filter(event)
        begin
          rbname = event.get(@sensor_field)
          if rbname.nil? || rbname.empty?
            @logger.warn("Sensor field '#{@sensor_field}' not found or empty in event")
            return
          end
      
          policy_id = @sensor_policy_map[rbname]
          if policy_id.nil?
            @logger.debug("No policy ID found for sensor name: #{rbname}")
            return
          end
      
          @logger.debug("Sensor '#{rbname}' maps to policy ID '#{policy_id}'")
      
          @key_mapping.each do |mapped_key, _target_key|
            original_value = event.get(mapped_key)
            @logger.warn("Original value: #{original_value}")
            next unless original_value
      
            ip_part = original_value.to_s.split(":").first
            memcached_key = "#{@memcached_namespace}:#{policy_id}:#{ip_part}"
      
            @logger.debug("Checking Memcached for key: #{memcached_key}")
            cache_value = @memcached_manager.get(memcached_key)
      
            if cache_value
              begin
                details = JSON.parse(cache_value)
                event.set("[#{mapped_key}_is_malicious]", "malicious")
      
                if details["source"]
                  event.set("[#{mapped_key}_malicious_source]", details["source"])
                end
      
                if details["weight"]
                  weight = details["weight"].to_f
                  score = (weight * 100).round(2)
                  event.set("[#{mapped_key}_malicious_score]", score)
                end
      
              rescue JSON::ParserError
                @logger.warn("Invalid JSON format in Memcached for key #{memcached_key}: #{cache_value}")
                event.set("[#{mapped_key}_is_malicious]", "malicious")
              end
            else
              @logger.debug("No value found in Memcached for key: #{memcached_key}")
            end
      
            # Nuevo código para verificar el país en la blacklist
            if event.get('src_country_code')
              src_country_code = event.get('src_country_code')
              memcached_country_key = "#{@memcached_namespace}:#{policy_id}:#{src_country_code}"
              @logger.debug("Checking Memcached for country key: #{memcached_country_key}")
              country_blacklisted = @memcached_manager.get(memcached_country_key)
      
              if country_blacklisted
                event.set("[#{mapped_key}_is_malicious]", "malicious_country")
                event.set("[#{mapped_key}_malicious_country_code]", src_country_code)
              end
            end
      
            if event.get('dst_country_code')
              dst_country_code = event.get('dst_country_code')
              memcached_country_key = "#{@memcached_namespace}:#{policy_id}:#{dst_country_code}"
              @logger.debug("Checking Memcached for country key: #{memcached_country_key}")
              country_blacklisted = @memcached_manager.get(memcached_country_key)
      
              if country_blacklisted
                event.set("[#{mapped_key}_is_malicious]", "malicious_country")
                event.set("[#{mapped_key}_malicious_country_code]", dst_country_code)
              end
            end
          end
      
          filter_matched(event)
        rescue => e
          @logger.error("Exception in FlowReputation filter: #{e.message}")
          @logger.debug("Backtrace: #{e.backtrace.join("\n")}")
          event.set('error_message', "An error occurred in FlowReputation filter")
          filter_matched(event)
        end
      end
      
    end
  end
end
