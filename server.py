import socket
import threading

HOST = "172.30.160.1"
PORT = 51666

# Fixed channels matching the client
channels = {
    "general": [],
    "off-topic": [],
    "memes": [],
    "intro": []
}

clients = []  # List of connected client sockets

def broadcast(message, channel, sender_socket=None):
    """Send message to all clients in a specific channel."""
    for client in channels[channel]:
        if client != sender_socket:
            try:
                client.sendall(message.encode("utf-8"))
            except:
                remove_client(client, channel)

def remove_client(client_socket, channel=None):
    if client_socket in clients:
        clients.remove(client_socket)
    if channel and client_socket in channels[channel]:
        channels[channel].remove(client_socket)
    try:
        client_socket.close()
    except:
        pass

def handle_client(client_socket):
    # Ask for username
    client_socket.sendall("Enter your username: ".encode("utf-8"))
    username = client_socket.recv(1024).decode("utf-8").strip()

    # Add to all channels (so they can receive messages from any channel)
    for ch in channels.keys():
        channels[ch].append(client_socket)
    clients.append(client_socket)

    print(f"{username} connected")

    while True:
        try:
            msg = client_socket.recv(1024).decode("utf-8")
            if not msg:
                break
            # Expecting format: "channel|username: message"
            try:
                channel, content = msg.split("|", 1)
            except ValueError:
                continue  # ignore malformed messages

            if channel in channels:
                broadcast(msg, channel, sender_socket=client_socket)
        except:
            break

    for ch in channels.keys():
        if client_socket in channels[ch]:
            channels[ch].remove(client_socket)
    if client_socket in clients:
        clients.remove(client_socket)
    client_socket.close()
    print(f"{username} disconnected")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"Server running on {HOST}:{PORT}")
    print("Waiting for connections...")

    while True:
        client_socket, addr = server.accept()
        print(f"New connection: {addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()