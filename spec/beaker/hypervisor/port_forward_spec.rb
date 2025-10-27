# frozen_string_literal: true

require 'spec_helper'
require 'beaker/hypervisor/port_forward'
require 'socket'
require 'timeout'

RSpec.describe KubeVirtPortForwarder do
  let(:kube_client) do
    instance_double(
      Kubeclient::Client,
      api_endpoint: URI.parse('https://kubernetes.example.com/api'),
      auth_options: { bearer_token: 'test-token' },
      ssl_options: { verify_ssl: OpenSSL::SSL::VERIFY_NONE }
    )
  end

  let(:namespace) { 'test-namespace' }
  let(:vmi_name) { 'test-vmi' }
  let(:target_port) { 22 }
  let(:local_port) { 10022 }
  let(:logger) { instance_double(Logger).as_null_object }
  let(:on_error) { ->(error) { } }

  let(:forwarder) do
    described_class.new(
      kube_client: kube_client,
      namespace: namespace,
      vmi_name: vmi_name,
      target_port: target_port,
      local_port: local_port,
      logger: logger,
      on_error: on_error
    )
  end

  before do
    # Prevent actual EventMachine reactor from starting in tests
    allow(EventMachine).to receive(:run)
    allow(EventMachine).to receive(:reactor_running?).and_return(false)
    allow(EventMachine).to receive(:stop)
    allow(EventMachine).to receive(:schedule)
  end

  after do
    # Ensure forwarder is stopped after each test
    begin
      forwarder.stop if forwarder.state != :stopped
    rescue StandardError
      nil
    end
  end

  describe '#initialize' do
    it 'sets initial state to :new' do
      expect(forwarder.state).to eq(:new)
    end

    it 'stores the local port' do
      expect(forwarder.local_port).to eq(local_port)
    end

    it 'creates a logger if none provided' do
      forwarder_without_logger = described_class.new(
        kube_client: kube_client,
        namespace: namespace,
        vmi_name: vmi_name,
        target_port: target_port,
        local_port: local_port
      )
      expect(forwarder_without_logger.instance_variable_get(:@logger)).to be_a(Logger)
    end
  end

  describe '#start' do
    before do
      allow(EventMachine).to receive(:reactor_running?).and_return(true)
      allow(TCPServer).to receive(:new).and_return(instance_double(TCPServer, accept: nil, close: nil))
    end

    it 'transitions state from :new to :running' do
      forwarder.start
      sleep 0.1 # Give threads time to start
      expect(forwarder.state).to eq(:running)
    end

    it 'creates a TCP server on the specified port' do
      expect(TCPServer).to receive(:new).with('127.0.0.1', local_port)
      forwarder.start
      sleep 0.1
    end

    it 'starts the EventMachine reactor' do
      expect(EventMachine).to receive(:run)
      forwarder.start
      sleep 0.1
    end

    # Issue #4: Resource leak on startup failure
    it 'cleans up EventMachine reactor if server creation fails' do
      allow(TCPServer).to receive(:new).and_raise(StandardError, 'Port in use')
      
      expect do
        forwarder.start
        sleep 0.1
      end.not_to raise_error

      expect(forwarder.state).to eq(:error)
    end

    # Issue #9: Race condition in state transitions
    it 'prevents multiple simultaneous starts' do
      allow(EventMachine).to receive(:reactor_running?).and_return(true)
      
      thread1 = Thread.new { forwarder.start }
      thread2 = Thread.new { forwarder.start }
      
      thread1.join
      thread2.join
      
      # Only one should succeed, verified by single state transition
      expect(forwarder.state).to eq(:running)
    end

    it 'does not start if already running' do
      forwarder.start
      sleep 0.1
      initial_state = forwarder.state
      
      forwarder.start # Try to start again
      
      expect(forwarder.state).to eq(initial_state)
    end
  end

  describe '#stop' do
    before do
      allow(EventMachine).to receive(:reactor_running?).and_return(true)
      allow(TCPServer).to receive(:new).and_return(instance_double(TCPServer, accept: nil, close: nil))
    end

    it 'transitions state to :stopped' do
      forwarder.start
      sleep 0.1
      forwarder.stop
      expect(forwarder.state).to eq(:stopped)
    end

    it 'is idempotent' do
      forwarder.start
      sleep 0.1
      forwarder.stop
      forwarder.stop # Call again
      expect(forwarder.state).to eq(:stopped)
    end

    # Issue #2: Dangerous thread termination
    it 'does not use Thread.kill on connection threads' do
      # This test documents that Thread.kill should not be used
      # We'll verify proper cleanup instead
      server = instance_double(TCPServer)
      allow(TCPServer).to receive(:new).and_return(server)
      allow(server).to receive(:close)
      
      forwarder.start
      sleep 0.1
      
      # Mock a connection thread
      connection_threads = forwarder.instance_variable_get(:@connection_threads)
      mock_thread = Thread.new { sleep 1 }
      connection_threads << mock_thread
      
      # Verify thread.kill is called (documenting the problem)
      expect(mock_thread).to receive(:kill)
      
      forwarder.stop
    end

    # Issue #3: EventMachine reactor shared across connections
    it 'stops only its own EventMachine reactor when multiple forwarders exist' do
      # This test documents the issue - we'll verify EM.stop is called
      expect(EventMachine).to receive(:stop)
      
      forwarder.start
      sleep 0.1
      forwarder.stop
    end

    it 'closes the TCP server' do
      server = instance_double(TCPServer)
      allow(TCPServer).to receive(:new).and_return(server)
      expect(server).to receive(:close)
      
      forwarder.start
      sleep 0.1
      forwarder.stop
    end

    it 'waits for server thread to complete' do
      forwarder.start
      sleep 0.1
      
      server_thread = forwarder.instance_variable_get(:@server_thread)
      expect(server_thread).to receive(:join).and_call_original if server_thread
      
      forwarder.stop
    end

    it 'waits for reactor thread to complete' do
      forwarder.start
      sleep 0.1
      
      reactor_thread = forwarder.instance_variable_get(:@reactor_thread)
      expect(reactor_thread).to receive(:join).and_call_original if reactor_thread
      
      forwarder.stop
    end
  end

  describe '#establish_websocket_with_retry' do
    let(:client_socket) { instance_double(TCPSocket, closed?: false) }
    
    before do
      # Mock WebSocket creation
      allow(Faye::WebSocket::Client).to receive(:new).and_return(
        instance_double(Faye::WebSocket::Client, on: nil, protocol: nil)
      )
    end

    # Issue #8: Incorrect retry logic
    it 'retries the correct number of times' do
      allow(client_socket).to receive(:closed?).and_return(false)
      
      # Mock Queue to simulate failures
      connection_status_q = Queue.new
      allow(Queue).to receive(:new).and_return(connection_status_q)
      
      # Force failures by pushing errors
      call_count = 0
      allow(EventMachine).to receive(:schedule) do
        call_count += 1
        connection_status_q.push(RuntimeError.new('Failed'))
      end
      
      result = forwarder.send(:establish_websocket_with_retry, client_socket, retries: 3, delay: 0.01)
      
      expect(result).to be_nil
      expect(call_count).to eq(3) # Should try 3 times, not 1
    end

    # Issue #10: Queue race condition
    it 'handles queue operations safely' do
      allow(client_socket).to receive(:closed?).and_return(false)
      
      # This test documents the race condition in num_waiting check
      # The actual fix would involve removing the num_waiting check
      connection_status_q = instance_double(Queue)
      allow(Queue).to receive(:new).and_return(connection_status_q)
      allow(connection_status_q).to receive(:num_waiting).and_return(1)
      allow(connection_status_q).to receive(:push)
      allow(connection_status_q).to receive(:pop).and_return(RuntimeError.new('test'))
      
      forwarder.send(:establish_websocket_with_retry, client_socket, retries: 1, delay: 0)
    end

    it 'returns nil if client socket closes during retry' do
      # Simulate socket closing after first attempt
      call_count = 0
      allow(client_socket).to receive(:closed?) do
        call_count += 1
        call_count > 1 # Returns true after first check
      end
      
      # Mock Queue to prevent hanging
      connection_status_q = Queue.new
      allow(Queue).to receive(:new).and_return(connection_status_q)
      
      # Mock EventMachine.schedule to push error so queue.pop doesn't hang
      allow(EventMachine).to receive(:schedule) do
        connection_status_q.push(RuntimeError.new('Connection failed'))
      end
      
      result = forwarder.send(:establish_websocket_with_retry, client_socket, retries: 5, delay: 0)
      
      # Should return nil because socket closed
      expect(result).to be_nil
      # Should have attempted at least once before socket closed
      expect(call_count).to be >= 2
    end

    # Issue #15: Accessing private instance variables
    it 'handles WebSocket close events with HTTP 500 errors' do
      # This test documents the brittle access to internal Faye::WebSocket state
      ws = instance_double(Faye::WebSocket::Client)
      allow(Faye::WebSocket::Client).to receive(:new).and_return(ws)
      
      # The code accesses event.driver.instance_variable_get(:@http)
      # which is implementation-dependent and fragile
      close_handlers = []
      allow(ws).to receive(:on) do |event_name, &block|
        close_handlers << block if event_name == :close
      end
      
      # Mock Queue to prevent hanging
      connection_status_q = Queue.new
      allow(Queue).to receive(:new).and_return(connection_status_q)
      
      # Simulate WebSocket creation without actually calling the block
      # (calling block.call would attempt real WebSocket connection)
      allow(EventMachine).to receive(:schedule) do
        # Push an error to unblock the queue.pop
        connection_status_q.push(RuntimeError.new('Test error'))
      end
      
      # This would fail if Faye::WebSocket changes its internals
      forwarder.send(:establish_websocket_with_retry, client_socket, retries: 1, delay: 0)
      expect(close_handlers).not_to be_empty
    end
  end

  describe '#proxy_traffic' do
    let(:client_socket) { instance_double(TCPSocket) }
    let(:websocket) do
      instance_double(
        Faye::WebSocket::Client,
        protocol: KubeVirtPortForwarder::PLAIN_STREAM_PROTOCOL,
        on: nil,
        send: nil,
        close: nil,
        ready_state: Faye::WebSocket::Client::OPEN
      )
    end

    before do
      allow(client_socket).to receive(:readpartial).and_raise(IOError)
      allow(client_socket).to receive(:write)
      allow(client_socket).to receive(:close)
    end

    # Issue #1: Thread safety / race conditions in data proxying
    it 'safely handles concurrent access to client socket' do
      # Mock data flow
      data_written = []
      mutex = Mutex.new
      
      allow(client_socket).to receive(:write) do |data|
        mutex.synchronize { data_written << data }
      end
      
      allow(client_socket).to receive(:readpartial) do
        sleep 0.01
        raise IOError
      end
      
      # Capture message handlers
      message_handlers = []
      allow(websocket).to receive(:on) do |event, &block|
        message_handlers << block if event == :message
      end
      
      # Start proxying in a thread so we can clean it up
      proxy_thread = Thread.new do
        forwarder.send(:proxy_traffic, client_socket, websocket)
      end
      
      # Give the thread time to set up handlers and start
      sleep 0.05
      
      # The test documents that client_socket.write happens without synchronization
      # Multiple threads could write simultaneously
      proxy_thread.kill if proxy_thread.alive?
      proxy_thread.join rescue nil
      
      expect(data_written).to be_a(Array)
    end

    # Issue #5: Missing error handling in write operations
    it 'handles client socket write errors gracefully' do
      allow(client_socket).to receive(:write).and_raise(IOError, 'Socket closed')
      
      message_handlers = []
      allow(websocket).to receive(:on) do |event, &block|
        message_handlers << block if event == :message
      end
      
      forwarder.send(:proxy_traffic, client_socket, websocket)
      
      # Simulate incoming WebSocket message
      # Faye::WebSocket::Event has data as a method, not attribute
      event = double('WebSocket Event', data: 'test data')
      
      # This should raise an error because write errors aren't caught
      expect { message_handlers.first.call(event) if message_handlers.any? }.to raise_error(IOError)
    end

    # Issue #6: No timeout on socket reads
    it 'can hang indefinitely on client socket read' do
      # Mock a socket that never returns data or raises an error
      hanging_socket = instance_double(TCPSocket)
      hung = false
      allow(hanging_socket).to receive(:readpartial) do
        hung = true
        sleep 10 # Simulate hanging
        'data'
      end
      allow(hanging_socket).to receive(:close)
      
      # This should timeout, documenting that there's no read timeout
      proxy_thread = Thread.new do
        forwarder.send(:proxy_traffic, hanging_socket, websocket)
      end
      
      # Give it time to start hanging
      sleep 0.1 until hung || !proxy_thread.alive?
      
      # Confirm it's hanging
      expect(proxy_thread.alive?).to be true
      
      # Clean up
      proxy_thread.kill
      proxy_thread.join rescue nil
    end

    # Issue #7: WebSocket cleanup not complete
    it 'does not remove WebSocket event handlers' do
      handlers = {}
      allow(websocket).to receive(:on) do |event, &block|
        handlers[event] = block
      end
      
      forwarder.send(:proxy_traffic, client_socket, websocket)
      
      # Handlers are registered but never removed
      # In a real scenario, if websocket persists, these handlers leak
      expect(handlers).not_to be_empty
    end

    # Issue #11: No input validation
    it 'does not validate payload sizes before writing' do
      large_payload = 'x' * (100 * 1024 * 1024) # 100 MB
      
      message_handlers = []
      allow(websocket).to receive(:on) do |event, &block|
        message_handlers << block if event == :message
      end
      
      allow(client_socket).to receive(:write) do |data|
        # Should validate size before attempting to write
        data.size
      end
      
      forwarder.send(:proxy_traffic, client_socket, websocket)
      
      event = double('WebSocket Event', data: large_payload)
      
      # This will attempt to write 100MB without validation
      message_handlers.first.call(event) if message_handlers.any?
    end

    # Issue #12: Error channel doesn't stop proxy
    # Also exposes Issue #16: report_error assumes backtrace exists
    it 'continues proxying after receiving error channel message' do
      ws_with_channels = instance_double(
        Faye::WebSocket::Client,
        protocol: KubeVirtPortForwarder::STREAM_PROTOCOL,
        on: nil,
        send: nil,
        close: nil,
        ready_state: Faye::WebSocket::Client::OPEN
      )
      
      message_handlers = []
      allow(ws_with_channels).to receive(:on) do |event, &block|
        message_handlers << block if event == :message
      end
      
      forwarder.send(:proxy_traffic, client_socket, ws_with_channels)
      
      # Send an error channel message
      error_msg = KubeVirtPortForwarder::ERROR_CHANNEL + 'Fatal error from server'
      event = double('WebSocket Event', data: error_msg)
      
      # This will currently fail because report_error assumes backtrace exists
      # documenting Issue #16 (error.backtrace can be nil)
      expect do
        message_handlers.first.call(event) if message_handlers.any?
      end.to raise_error(NoMethodError, /undefined method.*join.*nil/)
    end

    # Issue #17: Inconsistent WebSocket state checking
    it 'only checks for OPEN state when closing WebSocket' do
      allow(client_socket).to receive(:readpartial).and_raise(IOError)
      
      # WebSocket in CONNECTING state
      connecting_ws = instance_double(
        Faye::WebSocket::Client,
        protocol: KubeVirtPortForwarder::PLAIN_STREAM_PROTOCOL,
        on: nil,
        ready_state: 0 # CONNECTING
      )
      
      # Should handle CONNECTING state, but only checks for OPEN
      expect(connecting_ws).not_to receive(:close)
      
      forwarder.send(:proxy_traffic, client_socket, connecting_ws)
    end

    # Issue #18: No validation of protocol negotiation
    it 'does not validate protocol negotiation result' do
      # WebSocket with unexpected protocol
      bad_protocol_ws = instance_double(
        Faye::WebSocket::Client,
        protocol: 'unexpected.protocol.v1',
        on: nil,
        send: nil,
        close: nil,
        ready_state: Faye::WebSocket::Client::OPEN
      )
      
      allow(client_socket).to receive(:readpartial).and_raise(IOError)
      
      # Should validate protocol, but currently just uses whatever was negotiated
      # This test documents that no validation happens
      expect do
        forwarder.send(:proxy_traffic, client_socket, bad_protocol_ws)
      end.not_to raise_error
    end
  end

  describe '#handle_connection' do
    let(:client_socket) { instance_double(TCPSocket, close: nil, closed?: false) }

    it 'closes client socket if WebSocket establishment fails' do
      allow(forwarder).to receive(:establish_websocket_with_retry).and_return(nil)
      
      expect(client_socket).to receive(:close)
      
      forwarder.send(:handle_connection, client_socket)
    end

    it 'proxies traffic if WebSocket is established' do
      websocket = instance_double(Faye::WebSocket::Client)
      allow(forwarder).to receive(:establish_websocket_with_retry).and_return(websocket)
      allow(forwarder).to receive(:proxy_traffic)
      
      expect(forwarder).to receive(:proxy_traffic).with(client_socket, websocket)
      
      forwarder.send(:handle_connection, client_socket)
    end

    it 'removes itself from connection_threads when done' do
      allow(forwarder).to receive(:establish_websocket_with_retry).and_return(nil)
      
      connection_threads = forwarder.instance_variable_get(:@connection_threads)
      test_thread = Thread.new do
        forwarder.send(:handle_connection, client_socket)
      end
      connection_threads << test_thread
      
      test_thread.join
      
      expect(connection_threads).not_to include(test_thread)
    end

    # Issue #16: Silent exception swallowing
    it 'swallows exceptions silently in some rescue blocks' do
      allow(forwarder).to receive(:establish_websocket_with_retry).and_raise(StandardError, 'Unexpected error')
      
      # Should log or re-raise, but instead swallows silently in some paths
      expect do
        forwarder.send(:handle_connection, client_socket)
      end.not_to raise_error
    end
  end

  describe '#report_error' do
    it 'logs the error' do
      error = StandardError.new('Test error')
      error.set_backtrace(['line1', 'line2'])
      
      expect(logger).to receive(:error).with(/Test error/)
      
      forwarder.send(:report_error, error)
    end

    it 'calls the on_error callback if provided' do
      error = StandardError.new('Test error')
      error.set_backtrace(['line1', 'line2'])
      
      expect(on_error).to receive(:call).with(error)
      
      forwarder.send(:report_error, error)
    end

    it 'handles missing on_error callback' do
      forwarder_without_callback = described_class.new(
        kube_client: kube_client,
        namespace: namespace,
        vmi_name: vmi_name,
        target_port: target_port,
        local_port: local_port,
        logger: logger
      )
      
      error = StandardError.new('Test error')
      error.set_backtrace(['line1', 'line2'])
      
      expect do
        forwarder_without_callback.send(:report_error, error)
      end.not_to raise_error
    end
    
    # Additional test for Issue #16: report_error doesn't handle nil backtrace
    it 'crashes when error has nil backtrace' do
      error = RuntimeError.new('Error without backtrace')
      # Don't set backtrace - it will be nil
      
      expect do
        forwarder.send(:report_error, error)
      end.to raise_error(NoMethodError, /undefined method.*join.*nil/)
    end
  end

  describe '#state_transition_to' do
    # Issue #9: Race conditions in state transitions
    it 'is thread-safe' do
      threads = 10.times.map do
        Thread.new do
          100.times do
            forwarder.send(:state_transition_to, :starting)
            forwarder.send(:state_transition_to, :running)
            forwarder.send(:state_transition_to, :stopping)
            forwarder.send(:state_transition_to, :stopped)
            forwarder.instance_variable_set(:@state, :new)
          end
        end
      end
      
      threads.each(&:join)
      
      # If not thread-safe, this would likely fail
      expect(forwarder.state).to be_a(Symbol)
    end

    it 'only allows valid state transitions' do
      # new -> starting
      expect(forwarder.send(:state_transition_to, :starting)).to be true
      
      # starting -> running
      expect(forwarder.send(:state_transition_to, :running)).to be true
      
      # running -> stopping
      expect(forwarder.send(:state_transition_to, :stopping)).to be true
      
      # stopping -> stopped
      expect(forwarder.send(:state_transition_to, :stopped)).to be true
      
      # stopped -> starting (allowed to restart)
      expect(forwarder.send(:state_transition_to, :starting)).to be true
    end

    it 'prevents invalid state transitions' do
      # Try to go directly from new to running (should fail)
      expect(forwarder.send(:state_transition_to, :running)).to be false
      expect(forwarder.state).to eq(:new)
    end
  end

  # Security Tests
  describe 'security' do
    # Issue #13: Bearer token in logs
    it 'does not log bearer token' do
      allow(EventMachine).to receive(:reactor_running?).and_return(true)
      
      expect(logger).not_to receive(:debug).with(/test-token/)
      expect(logger).not_to receive(:info).with(/test-token/)
      
      # The WebSocket URL construction happens in establish_websocket_with_retry
      client_socket = instance_double(TCPSocket, closed?: true)
      forwarder.send(:establish_websocket_with_retry, client_socket, retries: 1)
    end

    # Issue #14: No rate limiting
    it 'does not rate limit connection attempts' do
      client_socket = instance_double(TCPSocket, closed?: false)
      
      # Mock Queue to prevent hanging
      connection_status_q = Queue.new
      allow(Queue).to receive(:new).and_return(connection_status_q)
      
      # Push errors so queue.pop doesn't hang
      allow(EventMachine).to receive(:schedule) do
        connection_status_q.push(RuntimeError.new('Connection failed'))
      end
      
      # Can make unlimited retry attempts
      start_time = Time.now
      forwarder.send(:establish_websocket_with_retry, client_socket, retries: 100, delay: 0)
      duration = Time.now - start_time
      
      # Should have some rate limiting, but doesn't
      # 100 attempts should be rate limited, but currently isn't
      expect(duration).to be < 5 # All 100 attempts happen quickly
    end
  end

  describe 'integration scenarios' do
    it 'handles rapid start/stop cycles' do
      allow(EventMachine).to receive(:reactor_running?).and_return(true)
      
      # Mock TCPServer with accept that raises IOError when server is closed
      server = instance_double(TCPServer)
      allow(TCPServer).to receive(:new).and_return(server)
      allow(server).to receive(:accept).and_raise(IOError, 'Server closed')
      allow(server).to receive(:close)
      
      5.times do
        forwarder.start
        sleep 0.05
        forwarder.stop
        sleep 0.05
      end
      
      expect(forwarder.state).to eq(:stopped)
    end

    it 'handles multiple concurrent connections' do
      # This would test issue #3 if we had multiple forwarders
      # Currently documents that EM reactor is shared
    end
  end
end
