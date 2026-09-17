import os
from flask import Flask, request, jsonify
import psycopg2
import hmac
import hashlib
import base64
import json
from datetime import datetime

app = Flask(__name__)

# Your Shopify webhook signing secret (from Settings > Notifications)

SHOPIFY_WEBHOOK_SECRET = os.environ.get("SHOPIFY_WEBHOOK_SECRET")

# Your Postgres connection details
DB_CONFIG = {
    "dbname": os.environ.get("DB_NAME"),
    "user": os.environ.get("DB_USER"),
    "password": os.environ.get("DB_PASSWORD"),
    "host": os.environ.get("DB_HOST"),
    "port": os.environ.get("DB_PORT")
}


def verify_webhook(data, hmac_header):
    digest = hmac.new(
        SHOPIFY_WEBHOOK_SECRET.encode("utf-8"),
        data,
        hashlib.sha256
    ).digest()
    computed_hmac = base64.b64encode(digest).decode()
    return hmac.compare_digest(computed_hmac, hmac_header)


@app.route("/webhook/order-created", methods=["POST"])
def order_created():
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256")
    data = request.get_data()

    if not hmac_header or not verify_webhook(data, hmac_header):
        return jsonify({"error": "Invalid signature"}), 401

    order = request.get_json()

    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO orders (shopify_order_id, order_number, customer_email,
                             total_price, currency, financial_status,
                             line_items, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (shopify_order_id) DO NOTHING
    """, (
        order.get("id"),
        order.get("name"),
        order.get("email"),
        order.get("total_price"),
        order.get("currency"),
        order.get("financial_status"),
        json.dumps(order.get("line_items")),
        order.get("created_at")
    ))
    conn.commit()
    cur.close()
    conn.close()

    print(f"Order {order.get('name')} inserted successfully.")
    return jsonify({"status": "received"}), 200


if __name__ == "__main__":
    app.run(port=5000, debug=True)
