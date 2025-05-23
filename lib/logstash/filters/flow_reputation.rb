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
      config :key_prefix, validate: :string, default: "rbflowrep"
      config :sensor_policy_map, validate: :hash, required: true

      def register
        begin
          @memcached_manager = MemcachedManager.new(@memcached_servers)

          # Parse sensor_policies
          @sensor_policy_map.each do |sensor_name, policy_config|
            next unless policy_config.is_a?(String)
          
            @sensor_policy_map[sensor_name] = JSON.parse(policy_config)
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
          sensor_name = event.get('sensor_name')
          return unless sensor_name && !sensor_name.empty?
      
          policy = @sensor_policy_map[sensor_name]

          # Check if policy is valid
          return unless policy['id'] && policy['name'] && policy['threshold']
      
          policy_id = policy['id'].to_s
     
          # Set default fields values 
          event.set('flow_reputation_category', 'clean')
          event.set('flow_reputation_score', 0)
      
          check_items = {
            'LAN_IP'  => event.get('lan_ip'),
            'WAN_IP'  => event.get('wan_ip'),
            'COUNTRY' => event.get('ip_country_code')
          }
      
          whitelist_matched = false
          blacklisted_origins = []
          weights = {}
      
          check_items.each do |origin, value|
            next unless value && !value.to_s.empty?
     
            # Firt we check if the key is whitelisted 
            memcached_key = "#{@key_prefix}:#{policy_id}:w:#{value.to_s}"
            @logger.debug("Checking Memcached for key: #{memcached_key}")
            memcached_value = @memcached_manager.get(memcached_key)
            
            if memcached_value
              whitelist_matched = true 
              next
            end
      
            # Then we check if key is blacklisted
            memcached_key = "#{@key_prefix}:#{policy_id}:b:#{value.to_s}"
            @logger.debug("Checking Memcached for key: #{memcached_key}")
            memcached_value = @memcached_manager.get(memcached_key)
            next unless memcached_value

            blacklisted_origins << origin
     
            # Clean memcached value 
            memcached_value = memcached_value.to_s.strip

            # Calculate weight
            if memcached_value == "1"
              weights[origin] = 1.0
            else
              begin
                details = JSON.parse(memcached_value)
                next unless details['weight'] && ['LAN_IP', 'WAN_IP'].include?(origin)

                weights[origin] = details['weight'].to_f
              rescue JSON::ParserError
                @logger.debug("Invalid JSON in Memcached for #{memcached_key}")
              end
            end
          end
      
          if blacklisted_origins.any?
            threshold = policy['threshold'].to_f rescue 0

            # Default score
            score = 100

            # Calculate score in case there are weights
            if weights.any?
              score = (weights.values.max * 100).round(2)
            end

            if score >= threshold
              event.set('flow_reputation_category', 'malicious')
              event.set('flow_reputation_name', policy['name'].to_s)
              event.set('flow_reputation_id', policy_id)
              event.set('flow_reputation_origin', blacklisted_origins.uniq.join(','))
              event.set('flow_reputation_score', score)
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
