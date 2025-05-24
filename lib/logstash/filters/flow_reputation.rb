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
      config :sensors_policies, validate: :hash, required: true

      def register
        begin
          @memcached_manager = MemcachedManager.new(@memcached_servers)

          # Parse sensor_policies
          @sensors_policies.each do |sensor_name, policy|
            next unless policy.is_a?(String)
          
            @sensors_policies[sensor_name] = JSON.parse(policy)
          end

        rescue => e
          @logger.error("Error initializing Memcached client: #{e.message}")
          @logger.error("Error parsing sensors_policies JSON: #{e.message}")
          @logger.debug("Backtrace: #{e.backtrace.join("\n")}")
          @memcached_manager = nil
        end
      end


      def filter(event)
        begin
          return unless @memcached_manager

          return unless @sensors_policies && @sensors_policies.any?

          sensor_name = event.get('sensor_name')
          return unless sensor_name && !sensor_name.empty?
      
          sensor_policy = @sensors_policies[sensor_name]
          return unless sensor_policy['id'] && sensor_policy['name'] && sensor_policy['threshold']
      
          flow_reputation_id = sensor_policy['id'].to_s
          flow_reputation_name = sensor_policy['name'].to_s
          flow_reputation_threshold = sensor_policy['threshold'].to_f rescue 0
          flow_reputation_category = 'clean'
          flow_reputation_score = 0
          flow_reputation_origin = nil
     
          indicators = {}

          lan_ip = event.get('lan_ip')
          indicators['LAN_IP'] = lan_ip if lan_ip

          wan_ip = event.get('wan_ip')
          indicators['WAN_IP'] = wan_ip if wan_ip

          country = event.get('ip_country_code')
          indicators['COUNTRY'] = country if country
           
          whitelisted_indicators = []
          blacklisted_indicators = []
          weights = {}
      
          indicators.each do |indicator, value|
            next unless value && !value.to_s.empty?
     
            # Firt we check if the key is whilisted
            memcached_key = "#{@key_prefix}:#{flow_reputation_id}:w:#{value.to_s}"
            @logger.debug("Checking if memcached key is whitelisted: #{memcached_key} ...")
            memcached_value = @memcached_manager.get(memcached_key)
             
            if memcached_value
              @logger.debug("Key #{memcached_key} is whitelisted.")
              whitelisted_indicators << indicator
              next
            end
      
            # Then we check if key is blacklisted
            memcached_key = "#{@key_prefix}:#{flow_reputation_id}:b:#{value.to_s}"
            @logger.debug("Checking if memcached key is blacklisted: #{memcached_key} ...")
            memcached_value = @memcached_manager.get(memcached_key)
            next unless memcached_value

            @logger.debug("Key #{memcached_key} is blacklisted.")
            blacklisted_indicators << indicator
     
            # Clean memcached value 
            memcached_value = memcached_value.to_s.strip

            # Calculate weight
            if memcached_value == "1"
              weights[indicator] = 1.0
            else
              next unless ['LAN_IP', 'WAN_IP'].include?(indicator)

              begin
                details = JSON.parse(memcached_value)
                next unless details['weight']

                weights[indicator] = details['weight'].to_f
              rescue JSON::ParserError
                @logger.debug("Invalid JSON in Memcached for #{memcached_key}")
              end
            end
          end
     
          blacklisted_indicators = blacklisted_indicators - whitelisted_indicators

          if blacklisted_indicators.any?

            # Calculate score in case there are weights or 100 (default malicious max score)
            flow_reputation_score = weights.any? ? (weights.values.max * 100).round(2) : 100

            if flow_reputation_score >= flow_reputation_threshold
              flow_reputation_category = 'malicious'
              flow_reputation_indicators = blacklisted_indicators.uniq.join(', ')
            end
          end

          event.set('flow_reputation_id', flow_reputation_id)
          event.set('flow_reputation_name', flow_reputation_name)
          event.set('flow_reputation_category', flow_reputation_category)
          event.set('flow_reputation_score', flow_reputation_score)
          event.set('flow_reputation_indicators', flow_reputation_indicators) if flow_reputation_indicators
      
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
