# dark_shadows_ops

# 🕵️‍♂️ Dark Shadows Ops 🗝️💥

**احمِ أسرارك في عمق الظلال المظلمة** — مشروع تشفير RedTeam احترافي مكتوب بـ **Python**  
يدعم:
- 🔒 تشفير ملفات أو مجلدات كاملة
- 🗝️ حماية المفتاح بكلمة مرور قوية (PBKDF2)
- 📜 استخدام AES-256 CBC مع IV متجدد
- ✅ HMAC للتحقق من النزاهة ومنع التزوير
- 📦 ضغط المجلدات تلقائيًا قبل التشفير

---

## ✨ **الفكرة**
> فلسفة DeepSec: «إنجازاتنا الحقيقية تبقى في الظل… ما يظهر للعالم هو فقط ضجيج لا قيمة له.»

- الـ **Ciphertext** عديم الفائدة دون المفتاح وكلمة المرور.
- كل ملف مشفّر يحمل توقيع HMAC — إذا حاول أحد تعديله، يُرفض تلقائيًا.
- المجلدات تُضغط أولًا (`tar.gz`) ثم تُشفّر.

---

## 🚀 **طريقة التنصيب**

```bash
# 1) أنشئ بيئة افتراضية (اختياري)
python3 -m venv venv
source venv/bin/activate

# 2) ثبّت المكتبة اللازمة
pip install cryptography



⚙️ طريقة التشغيل
📜 احفظ السكربت

    احفظ الكود في ملف: dark_shadows_ops.py

🔑 أول تشغيل — توليد المفتاح

python3 dark_shadows_ops.py

    سيطلب منك تعيين كلمة مرور قوية لحماية مفتاح التشفير.

    سيولّد:

        key.enc → مفتاح مشفّر بكلمة مرورك.

        salt.bin → لتحسين الأمان ضد هجمات التخمين.

🗂️ المهام
✅ 1) تشفير ملف منفرد

python3 dark_shadows_ops.py

    اختر 1

    أدخل اسم الملف — مثلًا secret.txt

    سينتج secret.txt.enc

✅ 2) تشفير مجلد كامل

python3 dark_shadows_ops.py

    اختر 2

    أدخل اسم المجلد — مثلًا myfolder/

    سيتم ضغط المجلد → myfolder.tar.gz ثم تشفيره → myfolder.tar.gz.enc

✅ 3) فك التشفير

python3 dark_shadows_ops.py

    اختر 3

    أدخل الملف المشفّر — مثلًا secret.txt.enc

    سينتج ملفًا مفكوك التشفير → secret.txt.dec

    إذا كان الملف مشفّرًا من مجلد مضغوط، استخرج .dec ببرنامج فك ضغط (tar -xvf).

🔐 آلية الأمان

✔️ التشفير: AES-256 CBC مع IV متجدّد لكل عملية.
✔️ حماية المفتاح: PBKDF2 + SALT.
✔️ سلامة البيانات: HMAC SHA-256 للتحقق من أي تلاعب.
✔️ لا يمكن فك الملف إلا بكلمة المرور الأصلية.
🔥 أمثلة الاستخدام

✅ تشفير ملف:

echo "DeepSec: Our success is hidden." > secret.txt
python3 dark_shadows_ops.py  # اختر Encrypt FILE

✅ تشفير مجلد:

mkdir secrets_folder
echo "Top Secret!" > secrets_folder/secret1.txt
echo "Never reveal!" > secrets_folder/secret2.txt

python3 dark_shadows_ops.py  # اختر Encrypt FOLDER

✅ فك التشفير:

python3 dark_shadows_ops.py  # اختر Decrypt
tar -xvf secrets_folder.tar.gz.dec




⚡ متطلبات التشغيل

    Python >= 3.7

    مكتبة cryptography



