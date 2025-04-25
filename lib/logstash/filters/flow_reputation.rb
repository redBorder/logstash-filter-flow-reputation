# frozen_string_literal: true

# logstash-filter-flow-reputation.rb

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

      config :memcached_servers, validate: :array, default: ["memcached.service:11211"]
      config :memcached_namespace, validate: :string, default: "rbflowrep"
      config :sensor_field, validate: :string, default: "sensor_name"
      config :sensor_policy_map, validate: :hash, required: true

      def register
        begin
          @memcached_manager = MemcachedManager.new(@memcached_servers)
          @sensor_policy_map.each do |key, val|
            if val.is_a?(String)
              @sensor_policy_map[key] = JSON.parse(val)
            end
          end
        rescue => e
          @logger.error("Error initializing Memcached client: #{e.message}")
          @logger.error("Error parsing sensor_policy_map JSON: #{e.message}")
          @logger.debug("Backtrace: #{e.backtrace.join("\n")}")
          @memcached_manager = nil
        end
      end

      def filter(event)
        begin
          rbname = event.get(@sensor_field)
          return unless rbname && !rbname.empty?
      
          policy = @sensor_policy_map[rbname]
          return unless policy && policy['id'] && policy['name']
      
          policy_id = policy['id']
          policy_name = policy['name']
      
          # Set default category and score only
          event.set('flow_reputation_category', 'clean')
          event.set('flow_reputation_score', 0)
      
          check_items = {
            'LAN_IP'      => event.get('lan_ip'),
            'WAN_IP'      => event.get('wan_ip'),
            'COUNTRY_SRC' => event.get('src_country_code'),
            'COUNTRY_DST' => event.get('dst_country_code')
          }
      
          origins_matched = []
          match_found = false
      
          check_items.each do |origin, value|
            next unless value && !value.empty?
          
            value_key = value.to_s.split(":").first
            memcached_key = "#{@memcached_namespace}:#{policy_id}:#{policy_name}:#{value_key}"
            @logger.debug("Checking Memcached for key: #{memcached_key}")
            cache_value = @memcached_manager.get(memcached_key)
          
            next unless cache_value
          
            match_found = true
            origins_matched << origin
          
            begin
              details = JSON.parse(cache_value)
              if details['weight']
                score = (details['weight'].to_f * 100).round(2)
                event.set('flow_reputation_score', score)
              end
            rescue JSON::ParserError
              @logger.warn("Invalid JSON format in Memcached for key #{memcached_key}: #{cache_value}")
            end
          end
          
          if match_found
            event.set('flow_reputation_category', 'malicious')
            event.set('flow_reputation_name', policy_name)
            event.set('flow_reputation_id', policy_id.to_s)
            event.set('flow_reputation_origin', origins_matched.join(','))
          end
      
          # Si hay orígenes válidos, se setean
          if origins_matched.any?
            event.set('flow_reputation_origin', origins_matched.join(","))
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
