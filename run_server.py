# run_server.py
import threading
from server.core import VPNServerCore
from server.web_app.app import create_app

if __name__ == "__main__":
    # 1. Initialize VPN Core
    server = VPNServerCore()
    
    # 2. Initialize and Start Flask Web App in a separate thread
    # Share the server instance so the portal can disconnect users
    flask_app = create_app(server, server.db)
    threading.Thread(
        target=lambda: flask_app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False), 
        daemon=True
    ).start()
    
    print("==================================================")
    print(" Starting MA3104 VPN Server")
    print(" Web Admin Panel running at: http://127.0.0.1:5000")
    print(" Press Ctrl+C to stop")
    print("==================================================")
    
    try:
        # 3. Start VPN Server
        server.start()
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping VPN Server...")