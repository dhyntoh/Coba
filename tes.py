# token_verification_api.py
from flask import Flask, request, jsonify
import sqlite3
import hashlib
from datetime import datetime

app = Flask(__name__)
DB_PATH = "/etc/xray/commercial.db"

@app.route('/verify_token', methods=['POST'])
def verify_token():
    data = request.json
    token = data.get('token')
    vps_ip = data.get('vps_ip')
    
    if not token or not vps_ip:
        return jsonify({
            'status': 'error',
            'message': 'Token and VPS IP are required'
        }), 400
    
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check token
    cursor.execute('''
        SELECT id, vps_ip, expiry_date, used 
        FROM installation_tokens 
        WHERE token_hash = ?
    ''', (token_hash,))
    
    token_data = cursor.fetchone()
    
    if not token_data:
        log_token_attempt(token_hash, vps_ip, 'FAIL', 'Token not found')
        return jsonify({
            'status': 'error',
            'message': 'Invalid token'
        }), 401
    
    token_id, allowed_ip, expiry_date, used = token_data
    
    # Check if already used
    if used:
        log_token_attempt(token_hash, vps_ip, 'FAIL', 'Token already used')
        return jsonify({
            'status': 'error', 
            'message': 'Token has already been used'
        }), 401
    
    # Check expiry
    if datetime.now() > datetime.fromisoformat(expiry_date):
        log_token_attempt(token_hash, vps_ip, 'FAIL', 'Token expired')
        return jsonify({
            'status': 'error',
            'message': 'Token has expired'
        }), 401
    
    # Check IP restriction
    if allowed_ip != 'any' and allowed_ip != vps_ip:
        log_token_attempt(token_hash, vps_ip, 'FAIL', f'IP mismatch: {allowed_ip}')
        return jsonify({
            'status': 'error',
            'message': 'Token not valid for this VPS IP'
        }), 401
    
    # Mark token as used
    cursor.execute('''
        UPDATE installation_tokens 
        SET used = 1, used_at = datetime('now'), used_by_vps = ?
        WHERE id = ?
    ''', (vps_ip, token_id))
    
    conn.commit()
    conn.close()
    
    log_token_attempt(token_hash, vps_ip, 'SUCCESS', 'Token validated')
    
    return jsonify({
        'status': 'success',
        'message': 'Token verified successfully'
    })

def log_token_attempt(token_hash, vps_ip, status, details):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get token ID
    cursor.execute('SELECT id FROM installation_tokens WHERE token_hash = ?', (token_hash,))
    token_data = cursor.fetchone()
    
    if token_data:
        token_id = token_data[0]
        cursor.execute('''
            INSERT INTO token_usage_logs (token_id, vps_ip, success, details)
            VALUES (?, ?, ?, ?)
        ''', (token_id, vps_ip, status, details))
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
