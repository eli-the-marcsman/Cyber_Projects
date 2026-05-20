from flask import Flask
from auth import auth
from tickets import tickets_bp
from dashboard import dashboard_bp
from views import views_bp
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

app.register_blueprint(auth)
app.register_blueprint(tickets_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(views_bp)

if __name__ == '__main__':
    app.run(debug=True)