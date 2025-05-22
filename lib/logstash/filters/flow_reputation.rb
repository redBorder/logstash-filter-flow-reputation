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
          return unless policy && policy['id']
      
          policy_id = policy['id'].to_s
      
          event.set('flow_reputation_category', 'clean')
          event.set('flow_reputation_score', 0)
          event.remove('flow_reputation_name')
          event.remove('flow_reputation_id')
          event.remove('flow_reputation_origin')
      
          check_items = {
            'LAN_IP'  => event.get('lan_ip'),
            'WAN_IP'  => event.get('wan_ip'),
            'COUNTRY' => event.get('ip_country_code')
          }
      
          whitelist_matched = false
          origins_matched = []
          weights = {}
          is_definite_blacklist = false
      
          check_items.each do |origin, value|
            next unless value && !value.to_s.empty?
      
            value_key = value.to_s.split(":").first
      
            %w[w b].each do |action|
              memcached_key = "#{@memcached_namespace}:#{policy_id}:#{action}:#{value_key}"
              @logger.debug("Checking Memcached for key: #{memcached_key}")
              cache_value = @memcached_manager.get(memcached_key)
              next unless cache_value
      
              if action == 'w'
                whitelist_matched = true
                break
              end
      
              origins_matched << origin
      
              cache_str = cache_value.to_s.strip
              if cache_str == "1"
                weights[origin] = 1.0
                is_definite_blacklist = true
              else
                begin
                  details = JSON.parse(cache_str)
                  if details['weight'] && ['LAN_IP', 'WAN_IP'].include?(origin)
                    weight = details['weight'].to_f
                    weights[origin] = weight
                    event.set('flow_reputation_source', details['source'].to_s) if details['source']
                  end
                rescue JSON::ParserError
                  @logger.debug("Invalid JSON in Memcached for #{memcached_key}")
                end
              end
      
              break
            end
      
            break if whitelist_matched
          end
      
          if whitelist_matched
            # Resultado limpio por whitelist
            event.set('flow_reputation_category', 'clean')
            event.set('flow_reputation_score', 0)
            event.remove('flow_reputation_name')
            event.remove('flow_reputation_id')
            event.remove('flow_reputation_origin')
          elsif !origins_matched.empty?
            max_score = if weights.any?
                          weights.values.max * 100
                        else
                          100
                        end
      
            threshold = policy['threshold'].to_f rescue 0.0
      
            if is_definite_blacklist || max_score >= threshold
              event.set('flow_reputation_category', 'malicious')
              event.set('flow_reputation_score', max_score.round(2))
              event.set('flow_reputation_name', policy['name'].to_s)
              event.set('flow_reputation_id', policy_id)
              event.set('flow_reputation_origin', origins_matched.uniq.join(','))
            else
              event.set('flow_reputation_category', 'clean')
              event.set('flow_reputation_score', 0)
              event.remove('flow_reputation_name')
              event.remove('flow_reputation_id')
              event.remove('flow_reputation_origin')
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
