# 🛡️ SOC Triage & Enrichment Toolkit

# 🛡️ أداة الفحص التلقائي وتوليد التقارير لمحللي الـ SOC

أداة خفيفة ومؤتمتة بلغة بايثون (Python)، مصممة لمساعدة محللي مركز عمليات الأمان (SOC) على تسريع عملية الفحص الأولي للبلاغات، فحص مؤشرات الاختراق (IOCs) عبر واجهات التهديدات الأمنية، وإنشاء تقارير بصيغة Markdown بشكل فوري.

---

## 🚀 المميزات الرئيسية

* **التحقق التلقائي من التهديدات:** الاستعلام تلقائياً عن طريق **VirusTotal API v3** لفحص عناوين الـ IP وقيم الـ Hashes (MD5/SHA256).
* **التعرف الذكي على الـ IOCs:** التمييز بذكاء بين عناوين الشبكات (IPs) وهاشات الملفات.
* **توليد التقارير تلقائياً:** إنشاء تقارير تحقيق جاهزة ونظيفة (`SOC_Triage_Report.md`) تتضمن إحصائيات الخطورة (Malicious, Suspicious, Harmless).
* **أمان البيئة:** استخدام ملفات `.env` لإدارة مفاتيح الـ API بسرية وأمان تامة.

---

## 🛠️ هيكل المشروع

```text
SOC-Triage-Toolkit/
│
├── main.py                 # ملف التشغيل الرئيسي
├── requirements.txt        # المكتبات البرمجية المطلوبة
├── .env                    # إعدادات مفاتيح الـ API (يتم استثنائها في git)
├── iocs.txt                # ملف تجريبي يحتوي على مؤشرات الاختراق
├── SOC_Triage_Report.md    # تقرير التحقيق الناتج تلقائياً
├── modules/
│   ├── __init__.py
│   ├── vt_checker.py       # موديول التكامل مع VirusTotal API
│   └── reporter.py         # موديول توليد تقارير الـ Markdown
└── screenshots/            # لقطات الشاشة وتوضيح عمل الأداة
```

## ⚙️ التثبيت والإعداد
1- نسخ المستودع (Clone):
```git clone [https://github.com/shrouqobaid/SOC-Triage-Toolkit.git](https://github.com/YOUR_USERNAME/SOC-Triage-Toolkit.git)
cd SOC-Triage-Toolkit```

2-إنشاء وتفعيل البيئة الافتراضية:
``` python3 -m venv venv
source venv/bin/activate```

3- تثبيت المتطلبات:
```pip install -r requirements.txt```

4- عداد مفتاح الـ API:
أنشئ ملف باسم .env في المجلد الرئيسي وأضف مفتاح VirusTotal الخاص بك:
```VIRUSTOTAL_API_KEY=your_actual_api_key_here```
## طريقة الاستخدام
قم بتشغيل الأداة عن طريق تمرير ملف نصي يحتوي على مؤشرات الاختراق (مؤشر واحد في كل سطر):
```python main.py -f iocs.txt```
## أمثلة ومخرجات الأداة
1. تنفيذ الأداة والفحص عبر الـ Terminal
2. معاينة التقرير الناتج بصيغة Markdown

