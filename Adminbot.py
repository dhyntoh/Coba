# admin_token_bot.py
import sqlite3
import datetime
import secrets
import hashlib
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

ADMIN_BOT_TOKEN = "8248259347:AAFHwfo0eytvsNbTt9PVinkbnL7dAIMPihk"
ADMIN_ID = 5407046882
DB_PATH = "/etc/xray/commercial.db"

class TokenManager:
    def __init__(self):
        self.db_path = DB_PATH
    
    def generate_token(self, duration_days, vps_ip=None):
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expiry_date = datetime.datetime.now() + datetime.timedelta(days=duration_days)
        
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('''
                INSERT INTO installation_tokens (token_hash, vps_ip, expiry_date)
                VALUES (?, ?, ?)
            ''', (token_hash, vps_ip, expiry_date))
            conn.commit()
            return raw_token
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()
    
    def list_tokens(self):
        conn = sqlite3.connect(self.db_path)
        tokens = conn.execute('''
            SELECT vps_ip, expiry_date, is_active 
            FROM installation_tokens 
            ORDER BY created_date DESC
        ''').fetchall()
        conn.close()
        return tokens
    
    def extend_token(self, vps_ip, additional_days):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            UPDATE installation_tokens 
            SET expiry_date = datetime(expiry_date, '+? days') 
            WHERE vps_ip = ?
        ''', (additional_days, vps_ip))
        conn.commit()
        conn.close()

token_manager = TokenManager()

async def admin_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    
    keyboard = [
        [InlineKeyboardButton("🔑 Generate Token", callback_data="generate_token")],
        [InlineKeyboardButton("📋 List Tokens", callback_data="list_tokens")],
        [InlineKeyboardButton("🔄 Extend Token", callback_data="extend_token")],
        [InlineKeyboardButton("📊 System Stats", callback_data="system_stats")]
    ]
    
    await update.message.reply_text(
        "👑 Admin Token Manager\n\n"
        "Manage installation tokens for commercial VPN system:",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def handle_generate_token(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    context.user_data['awaiting_token_duration'] = True
    await query.edit_message_text(
        "🔑 Generate New Token\n\n"
        "Please enter:\n"
        "<code>duration_days vps_ip</code>\n\n"
        "Example: <code>30 192.168.1.1</code>\n"
        "Leave IP empty for any VPS: <code>30</code>",
        parse_mode='HTML'
    )

async def handle_list_tokens(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    tokens = token_manager.list_tokens()
    
    if not tokens:
        await query.edit_message_text("No tokens found.")
        return
    
    tokens_text = "🔑 Active Installation Tokens:\n\n"
    for token in tokens:
        status = "✅ Active" if token[2] else "❌ Inactive"
        tokens_text += f"🖥️ IP: {token[0] or 'Any'}\n"
        tokens_text += f"📅 Expiry: {token[1][:16]}\n"
        tokens_text += f"Status: {status}\n\n"
    
    await query.edit_message_text(tokens_text)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    
    if context.user_data.get('awaiting_token_duration'):
        try:
            parts = update.message.text.split()
            duration_days = int(parts[0])
            vps_ip = parts[1] if len(parts) > 1 else None
            
            token = token_manager.generate_token(duration_days, vps_ip)
            
            if token:
                response = f"""
✅ Token Generated Successfully!

🔑 Token: <code>{token}</code>
📅 Duration: {duration_days} days
🖥️ VPS IP: {vps_ip or 'Any'}
⏰ Expires: {(datetime.datetime.now() + datetime.timedelta(days=duration_days)).strftime('%Y-%m-%d %H:%M')}

⚠️ Save this token securely!
"""
            else:
                response = "❌ Failed to generate token (IP might already have token)"
            
            await update.message.reply_text(response, parse_mode='HTML')
            context.user_data['awaiting_token_duration'] = False
            
        except Exception as e:
            await update.message.reply_text("❌ Invalid format! Use: <code>days ip</code>", parse_mode='HTML')

def main():
    application = Application.builder().token(ADMIN_BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", admin_start))
    application.add_handler(CallbackQueryHandler(handle_generate_token, pattern="^generate_token$"))
    application.add_handler(CallbackQueryHandler(handle_list_tokens, pattern="^list_tokens$"))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    application.run_polling()

if __name__ == '__main__':
    main()
