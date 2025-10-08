# /etc/xray/admin/admin_bot.py
import sqlite3
import logging
import secrets
import hashlib
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

# Admin configuration
ADMIN_BOT_TOKEN = "8248259347:AAFHwfo0eytvsNbTt9PVinkbnL7dAIMPihk"
ADMIN_ID = 5407046882
DB_PATH = "/etc/xray/commercial.db"

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class AdminTokenManager:
    def __init__(self):
        self.db_path = DB_PATH
        self.init_database()
    
    def init_database(self):
        """Initialize database tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        
        # Create tokens table if not exists
        conn.execute('''
            CREATE TABLE IF NOT EXISTS installation_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE,
                token_display TEXT,
                vps_ip TEXT DEFAULT 'any',
                expiry_date DATETIME,
                is_active BOOLEAN DEFAULT 1,
                used BOOLEAN DEFAULT 0,
                used_at DATETIME,
                used_by_vps TEXT,
                purpose TEXT,
                created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER DEFAULT 5407046882
            )
        ''')
        
        # Create token usage logs table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS token_usage_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id INTEGER,
                vps_ip TEXT,
                used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN,
                details TEXT,
                FOREIGN KEY(token_id) REFERENCES installation_tokens(id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    def generate_token(self, vps_ip="any", days=30, purpose="VPN Installation"):
        """Generate a new one-time use token"""
        # Generate secure token
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        # Create display token (first and last 8 characters for security)
        token_display = f"{raw_token[:8]}...{raw_token[-8:]}"
        
        expiry_date = datetime.now() + timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO installation_tokens 
                (token_hash, token_display, vps_ip, expiry_date, purpose)
                VALUES (?, ?, ?, ?, ?)
            ''', (token_hash, token_display, vps_ip, expiry_date, purpose))
            
            token_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"New token generated: ID {token_id} for IP {vps_ip}")
            
            return {
                'success': True,
                'token_id': token_id,
                'raw_token': raw_token,
                'token_display': token_display,
                'vps_ip': vps_ip,
                'expiry_date': expiry_date,
                'purpose': purpose
            }
            
        except sqlite3.IntegrityError:
            logger.error("Token hash collision - very rare!")
            return {'success': False, 'error': 'Token generation failed'}
        finally:
            conn.close()
    
    def get_my_tokens(self, admin_id):
        """Get all tokens created by the admin"""
        conn = sqlite3.connect(self.db_path)
        
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                id, token_display, vps_ip, expiry_date, used, purpose,
                datetime(created_date) as created_date,
                CASE 
                    WHEN used = 1 THEN datetime(used_at)
                    ELSE NULL 
                END as used_date
            FROM installation_tokens 
            WHERE created_by = ?
            ORDER BY created_date DESC
            LIMIT 50
        ''', (admin_id,))
        
        tokens = cursor.fetchall()
        conn.close()
        
        return tokens
    
    def get_token_stats(self, admin_id):
        """Get token statistics for the admin"""
        conn = sqlite3.connect(self.db_path)
        
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN used = 1 THEN 1 ELSE 0 END) as used,
                SUM(CASE WHEN used = 0 AND expiry_date > datetime('now') THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN used = 0 AND expiry_date < datetime('now') THEN 1 ELSE 0 END) as expired
            FROM installation_tokens 
            WHERE created_by = ?
        ''', (admin_id,))
        
        stats = cursor.fetchone()
        conn.close()
        
        return {
            'total': stats[0],
            'used': stats[1],
            'active': stats[2],
            'expired': stats[3]
        }
    
    def revoke_token(self, token_id, admin_id):
        """Revoke a specific token"""
        conn = sqlite3.connect(self.db_path)
        
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE installation_tokens 
            SET is_active = 0 
            WHERE id = ? AND created_by = ?
        ''', (token_id, admin_id))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        return affected > 0

# Initialize token manager
token_manager = AdminTokenManager()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("❌ Access denied! Admin only.")
        return
    
    welcome_text = """
👑 *Admin VPN Token Manager*

*Available Commands:*
/mytoken - View your generated tokens
/newtoken - Generate new installation token
/stats - Token statistics
/revoke <id> - Revoke a token

*Quick Actions:*
"""
    
    keyboard = [
        [InlineKeyboardButton("🆕 Generate Token", callback_data="generate_token")],
        [InlineKeyboardButton("📋 My Tokens", callback_data="my_tokens")],
        [InlineKeyboardButton("📊 Statistics", callback_data="token_stats")],
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        welcome_text, 
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )

async def mytoken_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /mytoken command - show admin's tokens"""
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("❌ Access denied! Admin only.")
        return
    
    await show_my_tokens(update, context)

async def show_my_tokens(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display admin's tokens"""
    tokens = token_manager.get_my_tokens(ADMIN_ID)
    
    if not tokens:
        await update.message.reply_text("📭 You haven't generated any tokens yet.")
        return
    
    # Get statistics
    stats = token_manager.get_token_stats(ADMIN_ID)
    
    header_text = f"""
🔐 *Your Installation Tokens*

*Statistics:*
📊 Total: {stats['total']}
✅ Used: {stats['used']}
🟢 Active: {stats['active']}
❌ Expired: {stats['expired']}

*Recent Tokens:*
"""
    
    token_text = ""
    for token in tokens[:10]:  # Show last 10 tokens
        token_id, display, vps_ip, expiry, used, purpose, created, used_date = token
        
        # Status emoji
        if used:
            status = "✅ USED"
            usage_info = f"Used on: {used_date}"
        elif datetime.now() > datetime.fromisoformat(expiry):
            status = "❌ EXPIRED"
            usage_info = f"Expired: {expiry}"
        else:
            status = "🟢 ACTIVE"
            usage_info = f"Expires: {expiry}"
        
        token_text += f"""
🔑 *Token ID:* `{token_id}`
📝 *Token:* `{display}`
🖥️ *VPS IP:* `{vps_ip}`
📅 *Created:* {created}
🎯 *Purpose:* {purpose}
📊 *Status:* {status}
{usage_info}
────────────────
"""
    
    # Add pagination if more than 10 tokens
    if len(tokens) > 10:
        token_text += f"\n📄 Showing 10 of {len(tokens)} tokens. Use /mytoken for full list."
    
    # Create keyboard with actions
    keyboard = [
        [InlineKeyboardButton("🆕 Generate New Token", callback_data="generate_token")],
        [InlineKeyboardButton("🔄 Refresh", callback_data="my_tokens")],
        [InlineKeyboardButton("📊 Full Statistics", callback_data="token_stats")],
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.callback_query:
        await update.callback_query.edit_message_text(
            header_text + token_text,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    else:
        await update.message.reply_text(
            header_text + token_text,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )

async def newtoken_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /newtoken command"""
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("❌ Access denied! Admin only.")
        return
    
    # Check if parameters provided with command
    if context.args:
        await process_token_generation(update, context, context.args)
    else:
        await prompt_token_details(update)

async def prompt_token_details(update: Update):
    """Prompt admin for token generation details"""
    text = """
🆕 *Generate New Installation Token*

Please provide token details in this format:
