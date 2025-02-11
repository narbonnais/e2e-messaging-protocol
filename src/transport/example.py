import asyncio
from .tcp_client_transport import TCPClientTransport
from .tcp_server_transport import TCPServerTransport


async def run_server(server: TCPServerTransport):
    await server.start()


async def example_server():
    # Create and configure server
    server = TCPServerTransport("127.0.0.1", 8000)

    # Define a request handler that echoes the data back
    async def echo_handler(data: bytes) -> bytes:
        print(f"Server received: {data.decode()}")
        return data  # Echo back the same data

    server.set_request_handler(echo_handler)
    return server


async def example_client():
    # Create and configure client
    client = TCPClientTransport(timeout=5.0)

    try:
        print("Connecting to server...")
        # Offload the blocking connect call to a thread.
        await asyncio.to_thread(client.connect, "127.0.0.1", 8000)

        messages = [
            b"Hello, server!",
            b"How are you?",
            b"Goodbye!"
        ]

        for message in messages:
            print(f"\nSending: {message.decode()}")
            # Offload the blocking send call to a thread.
            response = await asyncio.to_thread(client.send, message)
            print(f"Received: {response.decode()}")

    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        await asyncio.to_thread(client.disconnect)


async def main():
    # Start the server
    server = await example_server()
    server_task = asyncio.create_task(run_server(server))

    print("Starting server...")
    await asyncio.sleep(1)  # Give the server time to start

    # Run the client which sends multiple messages over one connection
    await example_client()

    # Clean up: stop the server and cancel the task
    await server.stop()
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass

if __name__ == "__main__":
    asyncio.run(main())
