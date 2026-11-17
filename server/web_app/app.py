from flask import Flask, request, render_template, redirect, url_for, make_response
import jwt
import datetime

SECRET_KEY = "ma3104_vpn_demo_secret"

def create_app(vpn_core, db_manager):
    app = Flask(__name__)
    
    def get_current_user():
        token = request.cookies.get('token')
        if not token: return None
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return data['user']
        except:
            return None

    @app.route('/')
    def index():
        user = get_current_user()
        if not user: return redirect(url_for('login'))
        if user == 'admin': return redirect(url_for('admin_dashboard'))
        return redirect(url_for('client_dashboard'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            remember = request.form.get('remember')
            
            if db_manager.verify_user(username, password) or (username == 'admin' and password == 'admin'):
                # JWT Authentication: 30 days if Remember Me, else 1 day
                exp_days = 30 if remember else 1
                exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=exp_days)
                token = jwt.encode({'user': username, 'exp': exp}, SECRET_KEY, algorithm="HS256")
                
                resp = make_response(redirect(url_for('index')))
                # HTTPOnly Cookie for Security
                resp.set_cookie('token', token, httponly=True, max_age=exp_days*86400)
                return resp
            return render_template('login.html', error="Invalid credentials or account blocked.")
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        resp = make_response(redirect(url_for('login')))
        resp.set_cookie('token', '', expires=0)
        return resp

    @app.route('/admin')
    def admin_dashboard():
        if get_current_user() != 'admin': return redirect(url_for('login'))
        users = db_manager.get_all_users()
        traffic = db_manager.get_traffic_logs()
        fw_logs = db_manager.get_firewall_logs()
        fw_rules = db_manager.get_all_firewall_rules()
        active_users = list(vpn_core.authenticated_clients.values())
        return render_template('admin_dashboard.html', users=users, traffic=traffic, fw_logs=fw_logs, fw_rules=fw_rules, active_users=active_users)

    @app.route('/admin/kick/<username>')
    def kick_user(username):
        if get_current_user() != 'admin': return redirect(url_for('login'))
        vpn_core.kick_user(username) # Disconnect the active tunnel
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/firewall/add', methods=['POST'])
    def add_fw_rule():
        if get_current_user() != 'admin': return redirect(url_for('login'))
        ip = request.form.get('ip') or None
        port = request.form.get('port') or None
        domain = request.form.get('domain') or None
        action = request.form.get('action')
        user = request.form.get('username') or None
        if port: port = int(port)
        db_manager.add_firewall_rule(ip, port, domain, action, user)
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/firewall/delete/<int:rule_id>')
    def del_fw_rule(rule_id):
        if get_current_user() != 'admin': return redirect(url_for('login'))
        db_manager.delete_firewall_rule(rule_id)
        return redirect(url_for('admin_dashboard'))

    @app.route('/client')
    def client_dashboard():
        user = get_current_user()
        if not user or user == 'admin': return redirect(url_for('login'))
        user_data = db_manager.get_user(user)
        is_active = user in vpn_core.authenticated_clients.values()
        
        # Calculate percentage for progress bar
        total = user_data[2]
        used = user_data[3]
        percent = min(100, int((used / total) * 100)) if total > 0 else 100
        
        return render_template('client_dashboard.html', user=user_data, is_active=is_active, percent=percent)

    @app.route('/client/buy')
    def buy_quota():
        user = get_current_user()
        if not user or user == 'admin': return redirect(url_for('login'))
        db_manager.add_quota(user, 1024 * 1024 * 1024) # Add 1GB
        return redirect(url_for('client_dashboard'))

    return app