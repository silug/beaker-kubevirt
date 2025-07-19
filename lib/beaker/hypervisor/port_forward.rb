require 'kubeclient'
require 'faye/websocket'
require 'eventmachine'
require 'socket'
require 'logger'
require 'thread'
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
  STREAM_PROTOCOL = 'v4.channel.k8s.io'.freeze

  # A KubeVirt-specific subprotocol for a raw, un-multiplexed data stream.
  PLAIN_STREAM_PROTOCOL = 'plain.kubevirt.io'.freeze

  # The channel byte for the primary data stream (stdin/stdout).
  DATA_CHANNEL = "\x00".freeze

  # The channel byte for the error stream from the server.
  ERROR_CHANNEL = "\x01".freeze

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
  end

  # Starts the local TCP server and the EventMachine reactor in background threads.
  def start
    return unless state_transition_to(:starting)

    @logger.info("Starting local proxy on 127.0.0.1:#{@local_port} for vmi://#{@namespace}/#{@vmi_name}:#{@target_port}")

    # Start the EventMachine reactor in a dedicated thread to handle WebSocket I/O.
    @reactor_thread = Thread.new { EventMachine.run }
    # Wait for the reactor to be running
    sleep 0.1 until EventMachine.reactor_running?

    @server = TCPServer.new('127.0.0.1', @local_port)
    state_transition_to(:running)

    @server_thread = Thread.new do
      loop do
        break if @state == :stopping

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

    threads_to_join.each do |thread|
      thread.kill # Ensure threads are terminated
      begin
        thread.join
      rescue StandardError
        nil
      end
    end

    # Stop the EventMachine reactor.
    EventMachine.stop if EventMachine.reactor_running?
    @reactor_thread&.join

    @logger.info('Port forwarder stopped.')
    state_transition_to(:stopped)
  end

  private

  # Handles a single client connection from start to finish.
  # @param client_socket [TCPSocket] The socket connected to the client.
  def handle_connection(client_socket)
    websocket = establish_websocket_with_retry(client_socket)
    if websocket
      @logger.info('Connection to VMI established. Proxying traffic.')
      proxy_traffic(client_socket, websocket)
    else
      @logger.error('Failed to establish connection to VMI after multiple retries. Closing client socket.')
      client_socket.close
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
    server_root = uri.dup
    server_root.path = uri.path.match(%r{^/k8s/clusters/[^/]+|^/api|^/apis/|/}).to_s.chomp('/')
    base_http_url = server_root.to_s
    base_ws_url = base_http_url.sub(/^http/, 'ws')
    url = "#{base_ws_url}/apis/subresources.kubevirt.io/v1/namespaces/#{@namespace}/virtualmachineinstances/#{@vmi_name}/portforward/#{@target_port}"
    @logger.debug("Constructed WebSocket URL: #{url}")

    auth_token = @kube_client.auth_options[:bearer_token]
    headers = { 'Authorization' => "Bearer #{auth_token}" }

    retries.times do |i|
      return nil if client_socket.closed?

      @logger.info("Attempt #{i + 1}: Connecting to VMI '#{@vmi_name}'...")

      connection_status_q = Queue.new

      EventMachine.schedule do
        protocols = [PLAIN_STREAM_PROTOCOL]
        ws = Faye::WebSocket::Client.new(url, protocols, headers: headers, tls: @kube_client.ssl_options)

        ws.on :open do |event|
          @logger.debug("WebSocket connection opened. Negotiated protocol: '#{ws.protocol}'.")
          connection_status_q.push(ws)
        end

        # --- Improved Error Reporting ---
        # This handler now attempts to parse the HTTP response body on a 500 error
        # to provide a more specific reason for the failure.
        ws.on :close do |event|
          err_msg = "WebSocket closed unexpectedly. Code: #{event.code}, Reason: #{event.reason}"

          # Check for the HTTP response object within the close event, which faye-websocket provides on handshake failure.
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
          connection_status_q.push(RuntimeError.new(err_msg)) if connection_status_q.num_waiting > 0
        end
        # --- End of Fix ---
      end

      result = connection_status_q.pop

      return result if result.is_a?(Faye::WebSocket::Client)

      # Success!

      @logger.warn("Attempt #{i + 1} failed. Retrying in #{delay} seconds...")
      sleep delay
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

    to_ws = Thread.new do
      loop do
        data = client_socket.readpartial(4096)
        if use_channels
          websocket.send(DATA_CHANNEL + data)
        else
          websocket.send(data)
        end
      end
    rescue EOFError, IOError, Errno::ECONNRESET
      @logger.debug('Client socket closed. Shutting down proxy.')
      begin
        websocket.close
      rescue StandardError
        nil
      end
    end

    websocket.on :message do |event|
      payload = event.data

      if use_channels
        channel = payload[0]
        case channel
        when DATA_CHANNEL
          client_socket.write(payload[1..-1])
        when ERROR_CHANNEL
          report_error(RuntimeError.new("Received error from server: #{payload[1..-1].inspect}"))
        else
          @logger.warn("Received message on unknown channel: #{channel.inspect}. Treating as raw data.")
          client_socket.write(payload)
        end
      else
        client_socket.write(payload)
      end
    end

    websocket.on :close do |event|
      @logger.info("WebSocket connection closed. Code: #{event.code}, Reason: #{event.reason}")
      begin
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
    log_message += "#{error.class}: #{error.message}\n#{error.backtrace.join("\n")}"
    @logger.error(log_message)
    @on_error&.call(error)
  end

  # Manages state transitions with thread safety.
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
end

# =============================================================================
# Usage Example
# =============================================================================
if __FILE__ == $0
  # --- Configuration ---
  KUBECONFIG_PATH = File.expand_path('~/.kube/config')
  VMI_NAMESPACE = 'default'
  VMI_NAME = 'my-test-vmi' # A VMI that has an SSH server running
  TARGET_PORT = 22
  LOCAL_PORT = 2222
  # ---------------------

  puts "Loading kubeconfig from #{KUBECONFIG_PATH}..."
  begin
    config = Kubeclient::Config.read(KUBECONFIG_PATH)
    context = config.context
    kube_client = Kubeclient::Client.new(
      context.api_endpoint,
      'v1',
      ssl_options: context.ssl_options,
      auth_options: context.auth_options,
    )
    kube_client.discover
  rescue StandardError => e
    puts "Failed to load kubeconfig or initialize client: #{e.message}"
    exit 1
  end
  puts "Kubernetes client initialized for context '#{config.current_context}'."
  puts "Connected to server version: #{kube_client.server_version}"

  logger = Logger.new($stdout, level: :info)
  errors = []
  error_handler = ->(error) { errors << error }

  forwarder = KubeVirtPortForwarder.new(
    kube_client: kube_client,
    namespace: VMI_NAMESPACE,
    vmi_name: VMI_NAME,
    target_port: TARGET_PORT,
    local_port: LOCAL_PORT,
    logger: logger,
    on_error: error_handler,
  )

  begin
    forwarder.start

    unless forwarder.state == :running
      puts 'Forwarder failed to start. Check logs for details.'
      exit 1
    end

    puts "\n"
    puts "Port forwarder is running. State: #{forwarder.state}"
    puts "You can now connect to the VMI's port #{TARGET_PORT} via localhost:#{LOCAL_PORT}"
    puts "Example: ssh user@127.0.0.1 -p #{LOCAL_PORT}"
    puts 'This example will run for 30 seconds...'
    puts "\n"

    sleep 30
  rescue Interrupt
    puts "\nCaught interrupt signal."
  ensure
    puts 'Shutting down the port forwarder...'
    forwarder.stop
    puts "Shutdown complete. State: #{forwarder.state}"

    if errors.any?
      puts "\n--- Encountered #{errors.count} error(s) during execution: ---"
      errors.each_with_index do |err, i|
        puts "Error ##{i + 1}: #{err.class} - #{err.message}"
        # puts err.backtrace.join("\n") # Uncomment for full stack trace
        puts '--------------------'
      end
    else
      puts "\nExecution finished without any captured errors."
    end
  end
end
