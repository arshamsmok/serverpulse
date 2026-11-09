# ⚡ ServerPulse

داشبورد مانیتورینگ زنده و تاریخچه‌دار برای سرور لینوکسی. نمایش CPU، RAM، دیسک، ترافیک، آپتایم، بار سیستم، موقعیت سرور، پینگ به چند کشور با جیتر و افت بسته، سرویس‌ها و هشدار تلگرام.

ساخته‌شده توسط **[ArshamSmok](https://github.com/arshamsmok)** · نسخه **v1.3.1** · [تغییرات نسخه‌ها](CHANGELOG.md)

![داشبورد ServerPulse](screenshots/dashboard.png)

![صفحه ورود](screenshots/login.png)

## ✨ امکانات

- **زنده:** CPU، RAM، دیسک، میانگین پینگ، دریافت و ارسال، آپتایم، بار سیستم (۱/۵/۱۵ دقیقه)
- **تاریخچه:** ذخیره هر ۶۰ ثانیه در SQLite و نمودار برای ۱ ساعت، ۲۴ ساعت یا ۷ روز. داده‌های قدیمی‌تر از ۸ روز حذف می‌شوند.
- **پینگ:** هر ۳۰ ثانیه با ۵ بسته به هر کشور، با میانگین، **جیتر** و **درصد افت بسته**
- **موقعیت سرور:** کشور، شهر، IP و ISP
- **سرویس‌ها:** وضعیت سرویس‌های systemd که خودتان تعیین می‌کنید
- **هشدار تلگرام:** وقتی CPU، RAM یا دیسک از حد مشخص بگذرد، یا پینگ به یکی از کشورها قطع شود، پیام می‌رسد؛ با زمان انتظار بین هشدارها و پیام برگشت به حالت عادی
- **ظاهر:** حاشیه‌های رنگی چرخشی برای هر کارت، با احترام به تنظیم «کاهش حرکت» سیستم
- **ورود:** صفحه ورود با نام کاربری و رمز؛ رمز به‌صورت هش ذخیره می‌شود

## 📦 دانلود

| فایل | لینک |
|---|---|
| صفحه مخزن | https://github.com/arshamsmok/serverpulse |
| دانلود کل پروژه (zip) | https://github.com/arshamsmok/serverpulse/archive/refs/heads/main.zip |
| app.py | https://raw.githubusercontent.com/arshamsmok/serverpulse/main/app.py |
| install.sh | https://raw.githubusercontent.com/arshamsmok/serverpulse/main/install.sh |

## 🚀 نصب سریع (یک دستور)

روی سرور اوبونتو یا دبیان:

```bash
sudo bash -c "$(curl -Ls https://raw.githubusercontent.com/arshamsmok/serverpulse/main/install.sh)"
```

اسکریپت این موارد را می‌پرسد:
1. نام کاربری و رمز ورود (اگر رمز را خالی بگذارید، رمز تصادفی ساخته می‌شود)
2. توکن ربات تلگرام و Chat ID برای هشدار (اختیاری؛ برای رد کردن Enter بزنید)

در پایان لینک ورود را نشان می‌دهد.

## 🛠 نصب دستی

```bash
git clone https://github.com/arshamsmok/serverpulse.git
cd serverpulse
sudo bash install.sh
```

یا بدون git:

```bash
wget https://github.com/arshamsmok/serverpulse/archive/refs/heads/main.zip
unzip main.zip && cd serverpulse-main
sudo bash install.sh
```

## 🔑 بعد از نصب

```
 لینک ورود : http://IP-سرور:8585/
 نام کاربری: admin
 رمز عبور  : ...
```

پورت پیش‌فرض `8585` است. برای تغییر آن:

```bash
sudo PORT=9000 bash -c "$(curl -Ls https://raw.githubusercontent.com/arshamsmok/serverpulse/main/install.sh)"
```

## 📲 راه‌اندازی هشدار تلگرام

1. در تلگرام با **@BotFather** یک ربات بسازید و توکن آن را بگیرید.
2. یک پیام به ربات خود بفرستید، سپس در مرورگر این آدرس را باز کنید (توکن را جایگزین کنید):
   `https://api.telegram.org/bot<TOKEN>/getUpdates`
   عدد `chat` → `id` را Chat ID بگیرید.
3. توکن و Chat ID را در `/etc/serverpulse/config.json` بخش `alerts` قرار دهید:

```json
"alerts": {
  "telegram_token": "123456:ABC...",
  "chat_id": "123456789",
  "cpu": 90,
  "ram": 90,
  "disk": 90,
  "cooldown": 900
}
```

4. سرویس را ری‌استارت کنید: `sudo systemctl restart serverpulse`

`cooldown` تعداد ثانیه بین دو هشدار تکراری برای یک مورد است (پیش‌فرض ۹۰۰ ثانیه).

> اجرای دوباره `install.sh` تنظیمات را بازنویسی می‌کند و دوباره توکن می‌پرسد.

## 🛠 سرویس‌ها

نام واحدهای systemd که می‌خواهید وضعیتشان را ببینید، در `services` تنظیم می‌شود:

```json
"services": ["serverpulse", "nginx", "ssh"]
```

هر سرویس با رنگ نشان داده می‌شود: سبز یعنی `active`، قرمز یعنی `failed`.

## 🔄 تغییر نام کاربری یا رمز

دوباره اسکریپت نصب را اجرا کنید. تنظیمات بازنویسی می‌شوند و سرویس ری‌استارت می‌شود.

## 📊 دستورات مفید

```bash
sudo systemctl status serverpulse      # وضعیت سرویس
sudo systemctl restart serverpulse     # ری‌استارت
sudo journalctl -u serverpulse -n 50   # لاگ برای پیدا کردن خطا
```

## 🗑 حذف کامل

```bash
sudo systemctl disable --now serverpulse
sudo rm -f /etc/systemd/system/serverpulse.service
sudo rm -rf /opt/serverpulse /etc/serverpulse /var/lib/serverpulse
sudo systemctl daemon-reload
```

## ⚙️ تنظیم هدف‌های پینگ

لیست `TARGETS` در `/opt/serverpulse/app.py` را ویرایش کنید:

| فیلد | توضیح |
|---|---|
| `ip` | آدرسی که پینگ می‌شود |
| `name` | نام سرویس برای نمایش |
| `country` | نام کشور برای نمایش |
| `code` | کد دو حرفی کشور (برای پرچم) |
| `lat`, `lng` | مختصات نقشه؛ اگر `None` باشد روی نقشه نمی‌آید |

بعد از ویرایش، سرویس را ری‌استارت کنید. فاصله پینگ‌گیری با `PING_INTERVAL` و تعداد بسته‌ها با `PING_COUNT` تنظیم می‌شود.

## 🔒 نکات امنیتی

- **HTTP:** لینک پیش‌فرض HTTP است و رمز بدون رمزنگاری ارسال می‌شود. برای استفاده عمومی، برنامه را پشت Nginx با گواهی SSL قرار دهید.
- **فایروال:** اگر `ufw` فعال است، پورت را باز کنید: `sudo ufw allow 8585/tcp`.
- **فایل تنظیمات:** `config.json` رمز هش‌شده و توکن تلگرام را دارد و دسترسی آن `600` است. آن را هرگز در گیت‌هاب commit نکنید.
- **پینگ anycast:** IPهایی مثل `8.8.8.8` یا `1.1.1.1` به نزدیک‌ترین مرکز داده می‌رسند، نه لزوماً به کشوری که نوشته‌اید. برای پینگ دقیق به یک کشور، IP یک سرور واقعی همان کشور را بگذارید.
- **ip-api:** موقعیت سرور از ip-api گرفته می‌شود که فقط برای استفاده غیرتجاری رایگان است و ساعتی یک بار پرس‌وجو می‌شود.
- **ping:** برای جیتر و افت بسته باید بسته `iputils-ping` نصب باشد (نصب‌کننده خودش نصب می‌کند).

## 📁 ساختار مخزن

```
serverpulse/
├── app.py          برنامه اصلی: API، تاریخچه، هشدار، صفحه ورود و داشبورد
├── install.sh      اسکریپت نصب خودکار
├── CHANGELOG.md    تاریخچه نسخه‌ها
├── .gitignore
├── README.md
└── screenshots/
    ├── dashboard.png
    └── login.png
```

## 👤 سازنده

**ArshamSmok**: https://github.com/arshamsmok
