# # from flask import Flask

# # app = Flask(__name__)

# # @app.route("/")
# # def home():
# #     return "Hello, Flask is working!"

# # if __name__ == "__main__":
# #     app.run(host="0.0.0.0", port=8080)



# from flask import Flask, request, jsonify
# from mailscout.scout import Scout  # Import Scout class

# app = Flask(__name__)
# scout = Scout()  # Initialize Scout

# @app.route("/")
# def home():
#     return "Flask is running!"

# # ✅ API to verify if an email is valid via SMTP
# @app.route("/verify", methods=["POST"])
# def verify_email():
#     data = request.get_json()
#     email = data.get("email")

#     if not email:
#         return jsonify({"error": "Email is required"}), 400

#     is_valid = scout.check_smtp(email)
#     return jsonify({"email": email, "valid": is_valid})

# # ✅ API to find valid emails for a given domain and name
# @app.route("/find", methods=["POST"])
# def find_emails():
#     data = request.get_json()
#     domain = data.get("domain")
#     names = data.get("names", [])

#     if not domain:
#         return jsonify({"error": "Domain is required"}), 400

#     valid_emails = scout.find_valid_emails(domain, names)
#     return jsonify({"domain": domain, "valid_emails": valid_emails})

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=8080)

from flask import Flask, request, jsonify
from mailscout.scout import Scout  # Import Scout class

app = Flask(__name__)
scout = Scout()  # Initialize Scout

@app.route("/")
def home():
    return "Flask is running!"

# ✅ API to verify if an email is valid via SMTP
@app.route("/verify", methods=["POST"])
def verify_email():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Call check_smtp and return detailed response
    result = scout.check_smtp(email)

    # Ensure expected response format
    response = {
        "email": email,
        "status": result.get("status", "unknown"),
        "message": result.get("message", ""),
        "user_name": result.get("user_name", ""),
        "domain": result.get("domain", ""),
        "mx": result.get("mx", ""),
        "connections": result.get("connections", 0),
        "time_exec": result.get("time_exec", 0)
    }

    return jsonify(response)

# ✅ API to find valid emails for a given domain and name
@app.route("/find", methods=["POST"])
def find_emails():
    data = request.get_json()
    domain = data.get("domain")
    names = data.get("names", [])

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    valid_emails = scout.find_valid_emails(domain, names)
    return jsonify({"domain": domain, "valid_emails": valid_emails})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

