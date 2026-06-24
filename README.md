# 🤖 BotHost V2 - Improved Telegram Bot Hosting Panel

Fixed, polished and enhanced version with:
- ✅ Working multi-user system with admin panel
- ✅ Direct bot access from Users list (click "Bots" → open server panel)
- ✅ Beautiful modern UI with Tailwind + smooth animations + better dashboard
- ✅ No default password hints in login
- ✅ Encrypted tokens, expiry, full file manager, live logs, package installer
- ✅ Even more polished experience (search, filters, quick actions)

## Quick Start (Local)

```bash
cd bothost_fixed
pip install -r requirements.txt

# Set secrets
export ADMIN_PASSWORD=yourstrongpass
export SECRET_KEY=supersecret123
export ENCRYPTION_KEY= (auto generated)

python app.py
```

Open http://localhost:5000 → login with your admin user.

Default first run creates `admin` user.

## Deploy (Render / Railway)

1. Push to GitHub
2. Connect repo on Render
3. Add env vars: ADMIN_PASSWORD, SECRET_KEY (auto), ENCRYPTION_KEY (auto)
4. Add Disk for persistent bots_data

## Key Improvements Made

- Fixed user creation completely
- Users table now shows bots count + direct "Bots" button → opens modal with clickable links to each user's /server pages
- Login page completely clean (no default creds shown)
- Dashboard: gorgeous cards, pulsing status, quick actions, keyboard shortcuts (?)
- Server page: clean tabs (Console / Files / Packages)
- Full animations & modern dark theme throughout
- Better error handling & ownership checks

Enjoy hosting bots! 🚀
