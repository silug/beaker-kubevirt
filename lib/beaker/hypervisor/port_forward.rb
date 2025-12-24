# frozen_string_literal: true

require 'kubeclient'
require 'faye/websocket'
require 'eventmachine'
require 'socket'
require 'logger'
require 'json'

# KubeVirtPortForwarder acts as a local TCP proxy for a port on a KubeVirt VMI.
# It handles the entire lifecycle of discovering the VMI, establishing a
# WebSocket connection via the Kubernetes API, and proxying data.
#
# It is designed to be resilient, handling retries internally so that a client
# (like Beaker's SSH client) can connect to the local port and simply wait
# until the VMI is ready.
#
# See the bottom of this file for a complete usage example.
#
class KubeVirtPortForwarder
  attr_reader :state, :local_port

  # The subprotocol required by the Kubernetes API for multiplexed streaming.
  # This protocol defines channels for stdin, stdout, stderr, and a special
  # error channel, which allows for out-of-band error reporting.
  STREAM_PROTOCOL = 'v4.channel.k8s.io'

  # A KubeVirt-specific subprotocol for a raw, un-multiplexed data stream.
  PLAIN_STREAM_PROTOCOL = 'plain.kubevirt.io'

  # The channel byte for the primary data stream (stdin/stdout).
  DATA_CHANNEL = "\x00"

  # The channel byte for the error stream from the server.
  ERROR_CHANNEL = "\x01"

  # Class-level tracking of EventMachine reactor ownership
  # EventMachine has a single global reactor, so we need to track which
  # forwarder instance started it to avoid stopping it prematurely
  @reactor_owner_mutex = Mutex.new
  @reactor_owner = nil

  class << self
    attr_accessor :reactor_owner_mutex, :reactor_owner
  end

  # @param kube_client [Kubeclient::Client] An initialized kubeclient client.
  # @param namespace [String] The Kubernetes namespace of the VMI.
  # @param vmi_name [String] The name of the VirtualMachineInstance.
  # @param target_port [Integer] The port inside the VMI to connect to (e.g., 22 for SSH).
  # @param local_port [Integer] The local TCP port to listen on.
  # @param logger [Logger] An optional logger instance.
  # @param on_error [Proc] An optional callback (proc or lambda) to handle errors.
  def initialize(kube_client:, namespace:, vmi_name:, target_port:, local_port:, logger: nil, on_error: nil)
    @kube_client = kube_client
    @namespace = namespace
    @vmi_name = vmi_name
    @target_port = target_port
    @local_port = local_port
    @on_error = on_error
    @logger = logger || Logger.new($stdout, level: :info)

    @state = :new
    @mutex = Mutex.new
    @server_thread = nil
    @reactor_thread = nil
    @connection_threads = []
    @shutdown = false
  end

  # Starts the local TCP server and the EventMachine reactor in background threads.
  def start
    return unless state_transition_to(:starting)

    @logger.info("Starting local proxy on 127.0.0.1:#{@local_port} for vmi://#{@namespace}/#{@vmi_name}:#{@target_port}")

    # Reset shutdown flag
    @shutdown = false

    # Start the EventMachine reactor in a dedicated thread to handle WebSocket I/O.
    # EventMachine has a single global reactor, so we need to check if it's already running
    start_reactor = false
    self.class.reactor_owner_mutex.synchronize do
      unless EventMachine.reactor_running?
        start_reactor = true
        self.class.reactor_owner = self
      end
    end

    if start_reactor
      @reactor_thread = Thread.new { EventMachine.run }
      # Wait for the reactor to be running
      sleep 0.1 until EventMachine.reactor_running?
      @logger.debug('Started EventMachine reactor (owned by this forwarder)')
    else
      @logger.debug('Using existing EventMachine reactor (owned by another forwarder)')
    end

    @server = TCPServer.new('127.0.0.1', @local_port)
    state_transition_to(:running)

    @server_thread = Thread.new do
      loop do
        break if @state == :stopping || @shutdown

        begin
          # Accept a connection from a client (e.g., Beaker's SSH).
          client_socket = @server.accept
          @logger.debug("Accepted connection from #{client_socket.peeraddr.join(':')}")

          # Handle the entire KubeVirt connection lifecycle in a new thread.
          conn_thread = Thread.new { handle_connection(client_socket) }
          @mutex.synchronize { @connection_threads << conn_thread }
        rescue IOError
          # This is expected when @server.close is called in stop()
          @logger.info("Server on port #{@local_port} is shutting down.")
          break
        end
      end
    end
  rescue StandardError => e
    report_error(e)
    state_transition_to(:error)
    stop # Attempt a clean shutdown on startup failure
  end

  # Stops the server, closes all active connections, and cleans up threads.
  # This method is designed to be idempotent.
  def stop
    return unless state_transition_to(:stopping)

    @logger.info("Stopping port forwarder for vmi://#{@namespace}/#{@vmi_name}:#{@target_port}")

    # Set shutdown flag to signal threads to stop gracefully
    @shutdown = true

    # Close the main server socket to stop accepting new connections.
    @server&.close
    @server = nil

    # Wait for the main server thread to finish.
    @server_thread&.join

    # Clean up any active connection threads.
    threads_to_join = []
    @mutex.synchronize do
      threads_to_join = @connection_threads.dup
      @connection_threads.clear
    end

    # Give threads a chance to terminate gracefully
    threads_to_join.each do |thread|
      # Raise an exception in the thread to interrupt blocking I/O
      thread.raise(IOError, 'Port forwarder shutting down') if thread.alive?
    end

    # Wait for threads to finish with a timeout
    deadline = Time.now + 5
    threads_to_join.each do |thread|
      remaining = deadline - Time.now
      if remaining.positive?
        # Wait for thread to finish, but don't wait longer than the deadline
        begin
          thread.join(remaining)
        rescue StandardError => e
          # Thread may raise an exception when we called thread.raise
          @logger.debug("Thread exited with exception during shutdown: #{e.class}: #{e.message}")
        end
      end

      # If thread is still alive after timeout, kill it as last resort
      next unless thread.alive?

      @logger.warn("Force-killing connection thread that didn't shut down gracefully")
      thread.kill
      begin
        thread.join
      rescue StandardError
        nil
      end
    end

    # Stop the EventMachine reactor only if this instance owns it.
    # EventMachine has a single global reactor, so we must not stop it
    # if other forwarders are still using it.
    should_stop_reactor = false
    self.class.reactor_owner_mutex.synchronize do
      if self.class.reactor_owner == self
        should_stop_reactor = true
        self.class.reactor_owner = nil
      end
    end

    if should_stop_reactor
      EventMachine.stop if EventMachine.reactor_running?
      @reactor_thread&.join
      @logger.debug('Stopped EventMachine reactor (owned by this forwarder)')
    else
      @logger.debug('Not stopping EventMachine reactor (owned by another forwarder)')
    end

    @logger.info('Port forwarder stopped.')
    state_transition_to(:stopped)
  end

  private

  # Handles a single client connection from start to finish.
  # @param client_socket [TCPSocket] The socket connected to the client.
  def handle_connection(client_socket)
    websocket = establish_websocket_with_retry(client_socket, retries: 1)
    if websocket
      @logger.info('Connection to VMI established. Proxying traffic.')
      proxy_traffic(client_socket, websocket)
    else
      @logger.error('Failed to establish connection to VMI. Closing client socket.')
      client_socket.close
    end
  rescue IOError => e
    # IOError is raised during shutdown - this is expected
    if e.is_a?(EOFError)
      @logger.debug('Connection closed cleanly (EOF) - normal shutdown')
    elsif e.message.include?('shutting down')
      @logger.debug('Connection handler shutting down gracefully')
    else
      report_error(e, 'Error in connection handler thread')
    end
    begin
      client_socket.close
    rescue StandardError
      nil
    end
  rescue StandardError => e
    report_error(e, 'Error in connection handler thread')
    begin
      client_socket.close
    rescue StandardError
      nil
    end
  ensure
    @mutex.synchronize { @connection_threads.delete(Thread.current) }
  end

  # Attempts to establish the WebSocket connection, retrying on failure.
  # This is the core of the "wait for VM" logic.
  # @param client_socket [TCPSocket] The client socket, used to check if the client is still connected.
  # @return [Faye::WebSocket::Client, nil] The connected WebSocket client or nil if it fails.
  def establish_websocket_with_retry(client_socket, retries: 10, delay: 5)
    uri = @kube_client.api_endpoint
    # Build base URL preserving any path prefix (e.g., /k8s/clusters/xyz in Rancher)
    base_url = "#{uri.scheme}://#{uri.host}"
    base_url += ":#{uri.port}" if uri.port && ![80, 443].include?(uri.port)
    # Preserve the path prefix if it exists, removing any trailing API paths
    path_prefix = uri.path.to_s.sub(%r{/api.*$}, '')
    base_url += path_prefix unless path_prefix.empty? || path_prefix == '/'
    base_ws_url = base_url.sub(/^http/, 'ws')
    url = "#{base_ws_url}/apis/subresources.kubevirt.io/v1/namespaces/#{@namespace}/virtualmachineinstances/#{@vmi_name}/portforward/#{@target_port}"
    @logger.debug("Constructed WebSocket URL: #{url}")

    auth_token = @kube_client.auth_options[:bearer_token]
    @logger.info("Using auth token: #{auth_token ? 'present' : 'absent'}")
    headers = {}
    headers['Authorization'] = "Bearer #{auth_token}" if auth_token && !auth_token.empty?

    # Convert kubeclient SSL options to Faye::WebSocket/EventMachine TLS options
    tls_options = convert_ssl_options_to_tls(@kube_client.ssl_options)

    retries.times do |i|
      return nil if client_socket.closed?

      @logger.info("Attempt #{i + 1}: Connecting to VMI '#{@vmi_name}'...")

      connection_status_q = Queue.new

      EventMachine.schedule do
        protocols = [PLAIN_STREAM_PROTOCOL]
        ws = Faye::WebSocket::Client.new(url, protocols, headers: headers, tls: tls_options)

        ws.on :open do |_event|
          @logger.debug("WebSocket connection opened. Negotiated protocol: '#{ws.protocol}'.")
          connection_status_q.push(ws)
        end

        # This handler now attempts to parse the HTTP response body on a 500 error
        # to provide a more specific reason for the failure.
        ws.on :close do |event|
          if event.code == 1000 # Normal closure
            @logger.info('WebSocket connection closed normally.')
          else
            err_msg = "WebSocket closed unexpectedly. Code: #{event.code}, Reason: #{event.reason}"

            # Check for the HTTP response object within the close event,
            # which faye-websocket provides on handshake failure.
            if event.instance_variable_defined?(:@driver) && event.driver.instance_variable_defined?(:@http)
              http_response = event.driver.instance_variable_get(:@http)
              if http_response && http_response.code == 500 && http_response.body
                begin
                  error_body = JSON.parse(http_response.body)
                  if error_body['message']
                    # This is the actual root cause from the server.
                    err_msg = "Server returned 500 Internal Server Error: #{error_body['message']}"
                  end
                rescue JSON::ParserError
                  # Body was not valid JSON, stick with the original error.
                end
              end
            end

            @logger.warn(err_msg)
            connection_status_q.push(RuntimeError.new(err_msg))
          end
        end
      rescue StandardError => e
        err_msg = "Failed to establish WebSocket connection: #{e.class}: #{e.message}"
        @logger.error(err_msg)
        connection_status_q.push(RuntimeError.new(err_msg))
      end

      result = connection_status_q.pop

      return result if result.is_a?(Faye::WebSocket::Client)

      # Success!
      unless retries == 1
        @logger.warn("Attempt #{i + 1} failed. Retrying in #{delay} seconds...")
        sleep delay
      end
    end
    nil # All retries failed.
  end

  # Proxies data in both directions between the client and the WebSocket.
  # @param client_socket [TCPSocket] The socket for the local client.
  # @param websocket [Faye::WebSocket::Client] The connected WebSocket.
  def proxy_traffic(client_socket, websocket)
    use_channels = (websocket.protocol == STREAM_PROTOCOL)
    if use_channels
      @logger.info("Using multiplexed stream protocol: #{STREAM_PROTOCOL}")
    else
      @logger.info("Using raw stream protocol (negotiated: '#{websocket.protocol || 'none'}')")
    end

    # Mutex to synchronize access to client_socket from multiple threads
    socket_mutex = Mutex.new

    # Read timeout to prevent hanging indefinitely
    read_timeout = 300 # 5 minutes

    to_ws = Thread.new do
      loop do
        # Use wait_readable to implement a read timeout
        unless client_socket.wait_readable(read_timeout)
          # Timeout occurred
          @logger.warn("Client socket read timeout after #{read_timeout} seconds. Closing connection.")
          break
        end

        data = client_socket.readpartial(4096)
        if use_channels
          websocket.send(DATA_CHANNEL + data)
        else
          websocket.send(data)
        end
      end
    rescue Errno::ECONNRESET, IOError => e
      if e.is_a?(EOFError)
        @logger.debug('Client connection closed cleanly (EOF). Shutting down proxy.')
      else
        @logger.debug("Client socket closed (#{e.class}: #{e.message}). Shutting down proxy.")
      end
      begin
        Timeout.timeout(5) do
          websocket.close if websocket.ready_state == Faye::WebSocket::Client::OPEN
        end
      rescue Timeout::Error
        @logger.warn('Timeout while closing WebSocket. It may have already been closed.')
      rescue StandardError => e
        @logger.warn("Failed to close WebSocket properly: #{e.message}")
        nil
      end
    end

    websocket.on :message do |event|
      payload = event.data

      # Synchronize writes to client_socket
      socket_mutex.synchronize do
        if use_channels
          channel = payload[0]
          case channel
          when DATA_CHANNEL
            client_socket.write(payload[1..])
          when ERROR_CHANNEL
            report_error(RuntimeError.new("Received error from server: #{payload[1..].inspect}"))
          else
            @logger.warn("Received message on unknown channel: #{channel.inspect}. Treating as raw data.")
            client_socket.write(payload)
          end
        else
          client_socket.write(payload)
        end
      rescue IOError, Errno::EPIPE, Errno::ECONNRESET => e
        @logger.debug("Failed to write to client socket: #{e.class}: #{e.message}")
        # Socket is closed or broken, ignore the error
      end
    end

    websocket.on :close do |event|
      @logger.info("WebSocket connection closed. Code: #{event.code}, Reason: #{event.reason}")
      socket_mutex.synchronize do
        client_socket.close
      rescue StandardError
        nil
      end
    end

    to_ws.join
  end

  # Centralized error reporting.
  def report_error(error, context = nil)
    log_message = "ERROR: #{context}: " if context
    log_message ||= 'ERROR: '
    log_message += "#{error.class}: #{error.message}"
    # Backtrace may be nil for manually constructed errors
    log_message += "\n#{error.backtrace.join("\n")}" if error.backtrace
    @logger.error(log_message)
    @on_error&.call(error)
  end

  # Manages state transitions with thread safety.
  # rubocop:disable Naming/PredicateMethod
  def state_transition_to(new_state)
    @mutex.synchronize do
      case new_state
      when :starting
        return false unless %i[new stopped].include?(@state)
      when :running
        return false unless [:starting].include?(@state)
      when :stopping
        return false unless %i[running error].include?(@state)
      when :stopped
        return false unless [:stopping].include?(@state)
      end
      @state = new_state
    end
    true
  end
  # rubocop:enable Naming/PredicateMethod

  # Convert kubeclient SSL options to Faye::WebSocket/EventMachine TLS options.
  # @param ssl_options [Hash] The SSL options from kubeclient
  # @return [Hash] TLS options compatible with Faye::WebSocket::Client
  def convert_ssl_options_to_tls(ssl_options)
    return {} if ssl_options.nil? || ssl_options.empty?

    tls_options = {}

    # Faye::WebSocket (built on EventMachine) supports custom CA certificates via the
    # :root_cert_file option. This enables proper SSL verification for in-cluster connections
    # with self-signed certificates.
    #
    # Note: :cert_chain_file is for client certificates, :root_cert_file is for CA certs

    # Pass CA certificate file for server verification
    if ssl_options[:ca_file]
      tls_options[:root_cert_file] = ssl_options[:ca_file]
      @logger.debug("Using CA certificate for server verification: #{ssl_options[:ca_file]}")
    end

    # Handle SSL verification setting
    # Faye::WebSocket uses :verify_peer (boolean), while kubeclient uses :verify_ssl (may be OpenSSL constant)
    if ssl_options.key?(:verify_ssl)
      verify_value = ssl_options[:verify_ssl]
      # Convert OpenSSL constants to boolean
      # OpenSSL::SSL::VERIFY_NONE = 0, OpenSSL::SSL::VERIFY_PEER = 1
      tls_options[:verify_peer] = if verify_value.is_a?(Integer)
                                    (verify_value != 0)
                                  else
                                    verify_value ? true : false
                                  end
      @logger.debug("SSL verification: #{verify_value} -> verify_peer: #{tls_options[:verify_peer]}")
    end
    # If verify_ssl is not specified, Faye::WebSocket defaults to verify_peer: true (secure default)

    # Pass through client certificates if present (for mutual TLS authentication)
    tls_options[:private_key_file] = ssl_options[:client_key] if ssl_options[:client_key]
    tls_options[:cert_chain_file] = ssl_options[:client_cert] if ssl_options[:client_cert]

    tls_options
  end
end
