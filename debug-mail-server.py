import socket
import asyncio

class CustomDebuggingServer:
    def __init__(self, host='localhost', port=1025):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    async def handle_client(self, client_socket, address):
        print(f"\n--- NEW CONNECTION from {address} ---")
        client_socket.sendall(b'220 localhost Simple Mail Transfer Service Ready\\r\\n')
        full_data = b''
        while True:
            try:
                data = await asyncio.get_event_loop().sock_recv(client_socket, 1024)
                if not data:
                    break
                full_data += data
                # A simple check for the end of the email data command
                if b'\\r\\n.\\r\\n' in full_data:
                    break
            except ConnectionResetError:
                break
            except Exception as e:
                print(f"An error occurred while receiving data: {e}")
                break

        print("--- RECEIVED DATA (EMAIL) ---")
        try:
            # Decode data as UTF-8, replacing errors
            print(full_data.decode('utf-8', errors='replace'))
        except Exception as e:
            print(f"Could not decode message data: {e}")
            print(full_datalog)
        print("--------- END DATA ---------")

        # Respond to client to allow clean shutdown
        client_socket.sendall(b'221 Bye\\r\\n')
        print(f"--- CONNECTION from {address} CLOSED ---\n")
        client_socket.close()

    async def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.setblocking(False)
        loop = asyncio.get_event_loop()

        print(f"Starting debug mail server on {self.host}:{self.port}...")
        print("Press Ctrl+C to stop.")

        while True:
            client, addr = await loop.sock_accept(self.server_socket)
            loop.create_task(self.handle_client(client, addr))

async def main():
    server = CustomDebuggingServer()
    try:
        await server.start()
    except KeyboardInterrupt:
        print("\nServer stopped by user.")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting.")
