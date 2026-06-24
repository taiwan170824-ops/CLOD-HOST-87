# 🤖 BotHost – Telegram Bot Hosting Panel

Apne multiple Telegram bots ko ek jagah host karo — free mein!

---

## ✨ Features

- **Multiple bots** ek saath host karo
- **Start / Stop / Restart** har bot ko dashboard se
- **Live Logs** — real-time output dekho
- **Code Editor** — browser se hi code edit karo
- **Quick Templates** — echo bot, command bot
- **Password protected** dashboard
- **~50 MB memory footprint** — free tier pe chalega

---

## 🚀 Kaise Deploy Karein

### Option 1: Render.com (Recommended – Free)

1. GitHub pe yeh project upload karo
2. [render.com](https://render.com) pe jaao → **New Web Service**
3. GitHub repo connect karo
4. Environment variables set karo:
   - `ADMIN_PASSWORD` → apna password
   - `SECRET_KEY` → koi bhi random string
5. Deploy ho jaayega!

### Option 2: Railway.app (Free $5 credit/month)

```bash
npm install -g @railway/cli
railway login
railway init
railway up
```

### Option 3: Local Machine

```bash
# Install dependencies
pip install -r requirements.txt

# Set password (optional, default: admin123)
export ADMIN_PASSWORD=yourpassword

# Run
python app.py
# Open http://localhost:5000
```

---

## ⚙️ Environment Variables

| Variable         | Default      | Description                     |
|------------------|--------------|---------------------------------|
| `ADMIN_PASSWORD` | `admin123`   | Dashboard login password        |
| `SECRET_KEY`     | (auto-gen)   | Flask session secret            |
| `PORT`           | `5000`       | Server port                     |

---

## 🤖 Bot Code Requirements

- Bot token mat hardcode karo — use karo `os.environ['BOT_TOKEN']`
- `python-telegram-bot` library available hai
- Example:

```python
import os
from telegram.ext import ApplicationBuilder, MessageHandler, filters

async def echo(update, context):
    await update.message.reply_text(update.message.text)

app = ApplicationBuilder().token(os.environ['BOT_TOKEN']).build()
app.add_handler(MessageHandler(filters.TEXT, echo))
app.run_polling()
```

---

## 📁 File Structure

```
bothost/
├── app.py              # Flask backend
├── requirements.txt    # Dependencies  
├── Procfile            # Gunicorn start command
├── render.yaml         # Render config
├── templates/
│   ├── login.html      # Login page
│   └── dashboard.html  # Main dashboard
└── bots_data/          # Auto-created at runtime
    ├── bots.json       # Bot configs
    ├── bot_xxx.py      # Bot scripts
    └── logs/           # Bot log files
```

---

## ⚠️ Notes

- Free hosting pe bots **sleep ho jaate hain** agar traffic nahi ho — UptimeRobot se ping karte raho
- Har bot ek alag Python process mein chalta hai
- Logs `/bots_data/logs/` mein save hote hain
