import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading

class DiscordStyleApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Pycord")
        self.geometry("900x600")
        self.configure(bg="#2f3136")

        self.username = None
        self.password = None
        self.server_ip = None
        self.server_port = None
        self.client_socket = None

        # Channel management (4 fixed channels)
        self.channels = {
            "general": [],
            "off-topic": [],
            "memes": [],
            "intro": []
        }
        self.current_channel = "general"

        self.login_screen()

    def login_screen(self):
        self.login_window = tk.Toplevel(self)
        self.login_window.title("Log in")
        self.login_window.geometry("300x200")
        self.login_window.configure(bg="#2f3136")
        self.login_window.grab_set()

        tk.Label(self.login_window, text="Username", bg="#2f3136", fg="white").pack(pady=5)
        self.username_entry = tk.Entry(self.login_window)
        self.username_entry.pack(pady=5)

        tk.Label(self.login_window, text="Password", bg="#2f3136", fg="white").pack(pady=5)
        self.password_entry = tk.Entry(self.login_window, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(self.login_window, text="Log In", command=self.after_login).pack(pady=10)

    def after_login(self):
        self.username = self.username_entry.get()
        self.password = self.password_entry.get()
        self.login_window.destroy()
        self.show_server_ip_popup()

    def show_server_ip_popup(self):
        self.server_ip_popup_window = tk.Toplevel(self)
        self.server_ip_popup_window.title("Connect to Server")
        self.server_ip_popup_window.geometry("250x150")
        self.server_ip_popup_window.configure(bg="#2f3136")
        self.server_ip_popup_window.grab_set()

        # IP input
        tk.Label(self.server_ip_popup_window, text="Server IP", bg="#2f3136", fg="white").pack(pady=5)
        self.ip_entry = tk.Entry(self.server_ip_popup_window)
        self.ip_entry.insert(0, "127.0.0.1")  # default
        self.ip_entry.pack(pady=5)

        # Port input
        tk.Label(self.server_ip_popup_window, text="Port", bg="#2f3136", fg="white").pack(pady=5)
        self.port_entry = tk.Entry(self.server_ip_popup_window)
        self.port_entry.insert(0, "12345")  # default port
        self.port_entry.pack(pady=5)

        tk.Button(
            self.server_ip_popup_window, 
            text="Connect", 
            command=self.connect_to_server
        ).pack(pady=10)

    def connect_to_server(self):
        self.server_ip = self.ip_entry.get().strip()
        port_str = self.port_entry.get().strip()

        if not self.server_ip or not port_str.isdigit():
            messagebox.showerror("Error", "Please enter a valid IP and port.")
            return

        self.server_port = int(port_str)

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, self.server_port))
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.server_ip_popup_window.destroy()
            self.create_widgets()
        except Exception as e:
            messagebox.showerror("Connection Failed", str(e))

    def disconnect_from_server(self):
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
        for widget in self.winfo_children():
            widget.destroy()
        self.show_server_ip_popup()

    def create_widgets(self):
        # Left sidebar (Server List)
        self.sidebar = tk.Frame(self, width=80, bg="#202225")
        self.sidebar.pack(side="left", fill="y")
        disconnect_button = tk.Button(
            self.sidebar, text="+", fg="white", bg="#36393f",
            font=("Arial", 18, "bold"), width=2, height=1,
            command=self.disconnect_from_server
        )
        disconnect_button.pack(pady=10)

        # Channel List
        self.channels_frame = tk.Frame(self, width=200, bg="#2f3136")
        self.channels_frame.pack(side="left", fill="y")

        self.channel_buttons = {}
        for channel in self.channels.keys():
            btn = tk.Button(
                self.channels_frame, text=f"# {channel}", fg="white", bg="#2f3136",
                anchor="w", relief="flat",
                command=lambda ch=channel: self.switch_channel(ch)
            )
            btn.pack(fill="x", padx=10, pady=5)
            self.channel_buttons[channel] = btn

        # Main Chat Area
        self.chat_frame = tk.Frame(self, bg="#36393f")
        self.chat_frame.pack(side="left", fill="both", expand=True)

        # Chat Display
        self.chat_display = scrolledtext.ScrolledText(
            self.chat_frame, wrap=tk.WORD, bg="#36393f", fg="white",
            font=("Arial", 11), state="disabled"
        )
        self.chat_display.pack(fill="both", expand=True, padx=10, pady=(10, 5))

        # Entry Field
        self.entry_field = tk.Entry(
            self.chat_frame, font=("Arial", 11),
            bg="#40444b", fg="white", insertbackground="white"
        )
        self.entry_field.pack(fill="x", padx=10, pady=(0, 10))
        self.entry_field.bind("<Return>", self.send_message)

        # Show initial channel
        self.switch_channel("general")

    def switch_channel(self, channel_name):
        """Switch between channels and load their messages."""
        self.current_channel = channel_name
        self.chat_display.configure(state="normal")
        self.chat_display.delete("1.0", tk.END)
        for msg in self.channels[channel_name]:
            self.chat_display.insert(tk.END, msg + "\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.yview(tk.END)

    def send_message(self, event):
        message = self.entry_field.get().strip()
        if message and self.client_socket:
            try:
                full_msg = f"{self.current_channel}|{self.username}: {message}"
                self.client_socket.sendall(full_msg.encode("utf-8"))
                # Also add to local log
                self.channels[self.current_channel].append(f"{self.username}: {message}")
                self.display_message(f"{self.username}: {message}")
                self.entry_field.delete(0, tk.END)
            except:
                self.display_message("[Error] Failed to send message.")

    def receive_messages(self):
        while True:
            try:
                msg = self.client_socket.recv(1024).decode("utf-8")
                if msg:
                    try:
                        channel, content = msg.split("|", 1)
                    except ValueError:
                        continue  # skip malformed messages

                    if channel in self.channels:
                        self.channels[channel].append(content)
                        if channel == self.current_channel:
                            self.display_message(content)
            except:
                break

    def display_message(self, message):
        self.chat_display.configure(state="normal")
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.yview(tk.END)


if __name__ == "__main__":
    app = DiscordStyleApp()
    app.mainloop()