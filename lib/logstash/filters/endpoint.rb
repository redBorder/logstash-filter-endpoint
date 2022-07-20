# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require_relative "util/endpoint_constant"
require_relative "util/aerospike_config"
require_relative "store/aerospike_store"

class LogStash::Filters::Endpoint < LogStash::Filters::Base
  include EndpointConstant
  include Aerospike

  config_name "endpoint"

  config :aerospike_server,          :validate => :string,  :default => "",                             :required => false
  config :aerospike_namespace,       :validate => :string,  :default => "malware",                      :required => false
  config :reputation_servers,        :validate => :array,   :default => ["127.0.0.1:7777"],             :require => false

  public
  def register
    # Add instance variables
    @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
    @aerospike = Client.new(@aerospike_server.first.split(":").first)
    @aerospike_store = AerospikeStore.new(@aerospike, @aerospike_namespace,  @reputation_servers)
  end # def register

  public

  def size_to_range(size)
    range  = nil
    if (size < 1024)
        range =  "<1kB"
    elsif(size >= 1024 && size < (1024*1024))
        range = "1kB-1MB"
    elsif(size >= (1024*1024) && size < (10*1024*1024))
        range = "1MB-10MB"
    elsif(size >= (10*1024*1024) && size < (50*1024*1024))
        range = "10MB-50MB"
    elsif(size >= (50*1024*1024) && size < (100*1024*1024))
        range = "50MB-100MB"
    elsif(size >= (100*1024*1024) && size < (500*1024*1024))
        range = "100MB-500MB"
    elsif(size >= (500*1024*1024) && size < (1024*1024*1024))
        range = "500MB-1GB"
    elsif(size >= (1024*1024*1024))
        range = ">1GB"
    end

    return range
  end

  def filter(event)
    message = {}
    message = event.to_hash

    generated_events = [] 

    hash = message[HASH]
    timestamp = message[TIMESTAMP]

    @aerospike_store.update_hash_times(timestamp, hash, "hash")

    endpoint_uuid = message[ENDPOINT_UUID]

    message[SENSOR_UUID] = endpoint_uuid

    msg_hash_scores = @aerospike_store.enrich_hash_scores(message)
    msg_hash_scores[TYPE] = "endpoint"
        
    generated_events.push(LogStash::Event.new(msg_hash_scores))

    generated_events.each do |e|
      yield e
    end
    event.cancel
  end  # def filter(event)
end # class LogStash::Filters::Endpoint
