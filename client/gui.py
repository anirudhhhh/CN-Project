# client/gui.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import customtkinter as ctk
import threading
from client.core import VPNClientCore

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

COLOR_PRIMARY = "#D47E30"
COLOR_PRIMARY_HOVER = "#8D5A2B"
COLOR_DISCONNECT = "#e74c3c"
COLOR_DISCONNECT_HOVER = "#c0392b"

class VPNClientApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("MA3104 VPN")
        self.geometry("400x650") # Window dimensions
        self.resizable(False, False)
        
        self.is_connected = False
        self.vpn_core = None
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1) 
        self.grid_rowconfigure(1, weight=0) # Title
        self.grid_rowconfigure(2, weight=0) # Username
        self.grid_rowconfigure(3, weight=0) # Password
        self.grid_rowconfigure(4, weight=0) # Button
        self.grid_rowconfigure(5, weight=0) # Switch
        self.grid_rowconfigure(6, weight=0) # Mode comment
        self.grid_rowconfigure(7, weight=0) # Status
        self.grid_rowconfigure(8, weight=1) 
        
        self.setup_ui()
        
    def setup_ui(self):
        self.title_label = ctk.CTkLabel(
            self, text="MA3104 VPN", font=ctk.CTkFont(family="Helvetica", size=24, weight="bold")
        )
        self.title_label.grid(row=1, column=0, pady=(0, 30))
        
        # Username and password fields
        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username", width=200)
        self.username_entry.grid(row=2, column=0, pady=(0, 10))
        
        self.password_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*", width=200)
        self.password_entry.grid(row=3, column=0, pady=(0, 30))
        
        self.connect_btn = ctk.CTkButton(
            self, text="Connect", font=ctk.CTkFont(family="Helvetica", size=20, weight="bold"),
            width=140, height=140, corner_radius=70, fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER, command=self.toggle_connection
        )
        self.connect_btn.grid(row=4, column=0, pady=10)
        
        self.mode_var = ctk.StringVar(value="off")
        self.mode_switch = ctk.CTkSwitch(
            self, text="TUN Mode", variable=self.mode_var, onvalue="on", offvalue="off",
            command=self.mode_switch_event, font=ctk.CTkFont(family="Helvetica", size=16)
        )
        self.mode_switch.grid(row=5, column=0, pady=(20, 5))

        self.mode_comment_label = ctk.CTkLabel(
            self, text="You are in proxy mode", text_color="#888888", font=ctk.CTkFont(family="Helvetica", size=12)
        )
        self.mode_comment_label.grid(row=6, column=0, pady=(0, 20))
        
        self.status_label = ctk.CTkLabel(
            self, text="Disconnected", text_color="#e74c3c", font=ctk.CTkFont(family="Helvetica", size=18, weight="bold")
        )
        self.status_label.grid(row=7, column=0, pady=10)

    def mode_switch_event(self):
        current_state = self.mode_var.get()
        if current_state == "on":
            self.mode_comment_label.configure(text="You are in TUN mode")
        else:
            self.mode_comment_label.configure(text="You are in proxy mode")

    def toggle_connection(self):
        if not self.is_connected:
            self.connect()
        else:
            self.disconnect()

    def connect(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.on_connection_status_change("Error: Missing Credentials")
            return

        self.connect_btn.configure(state="disabled")
        self.status_label.configure(text="Authenticating...", text_color="#f39c12")
        self.username_entry.configure(state="disabled")
        self.password_entry.configure(state="disabled")
        
        mode = "TUN" if self.mode_var.get() == "on" else "Proxy"
        
        try:
            self.vpn_core = VPNClientCore(
                server_ip="127.0.0.1", server_port=9090, mode=mode, 
                username=username, password=password, # Pass credentials
                status_callback=self.on_connection_status_change
            )
            threading.Thread(target=self._start_vpn_core, daemon=True).start()
        except Exception as e:
            self.on_connection_status_change(f"Error: {e}")

    def _start_vpn_core(self):
        try:
            self.vpn_core.start()
        except Exception as e:
            self.on_connection_status_change(f"Error: {e}")

    def on_connection_status_change(self, status_msg):
        self.after(0, self._update_status_ui, status_msg)

    def _update_status_ui(self, status_msg):
        if status_msg == "Connected":
            self.is_connected = True
            self.connect_btn.configure(state="normal", text="Disconnect", fg_color=COLOR_DISCONNECT, hover_color=COLOR_DISCONNECT_HOVER)
            mode_text = "TUN Mode" if self.mode_var.get() == "on" else "Proxy Mode"
            self.status_label.configure(text=f"Connected via {mode_text}", text_color="#2ecc71")
            self.mode_switch.configure(state="disabled")
            
        elif status_msg == "Disconnected":
            self.is_connected = False
            self.connect_btn.configure(state="normal", text="Connect", fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER)
            self.status_label.configure(text="Disconnected", text_color="#e74c3c")
            self.mode_switch.configure(state="normal")
            self.username_entry.configure(state="normal")
            self.password_entry.configure(state="normal")
            
        else:
            self.is_connected = False
            self.connect_btn.configure(state="normal", text="Connect", fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER)
            self.status_label.configure(text=status_msg, text_color="#e74c3c")
            self.mode_switch.configure(state="normal")
            self.username_entry.configure(state="normal")
            self.password_entry.configure(state="normal")
            if self.vpn_core:
                self.vpn_core.stop()

    def disconnect(self):
        if self.vpn_core:
            self.vpn_core.stop()
            self.vpn_core = None
        self._update_status_ui("Disconnected")

if __name__ == "__main__":
    app = VPNClientApp()
    app.mainloop()