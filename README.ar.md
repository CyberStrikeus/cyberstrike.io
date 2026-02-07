<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>إطار عمل ذكي للاختبارات الأمنية الاختراقية المستقلة.</strong></p>
<p align="center">
  <a href="https://cyberstrike.io/discord"><img alt="Discord" src="https://img.shields.io/discord/1391832426048651334?style=flat-square&label=discord" /></a>
  <a href="https://www.npmjs.com/package/cyberstrike"><img alt="npm" src="https://img.shields.io/npm/v/cyberstrike?style=flat-square" /></a>
  <a href="https://github.com/CyberStrikeus/cyberstrike.io/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/CyberStrikeus/cyberstrike.io?style=flat-square" /></a>
  <a href="https://github.com/CyberStrikeus/cyberstrike.io/blob/dev/LICENSE"><img alt="License" src="https://img.shields.io/github/license/CyberStrikeus/cyberstrike.io?style=flat-square" /></a>
</p>

<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zht.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="README.de.md">Deutsch</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.fr.md">Français</a> |
  <a href="README.it.md">Italiano</a> |
  <a href="README.da.md">Dansk</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.pl.md">Polski</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.ar.md">العربية</a> |
  <a href="README.no.md">Norsk</a> |
  <a href="README.br.md">Português (Brasil)</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/CyberStrikeus/docs/main/public/docs/images/gifs/g01-first-run.gif" alt="CyberStrike Demo" width="700">
</p>

---

## ما هو CyberStrike؟

CyberStrike هو إطار عمل مفتوح المصدر لاختبار الاختراق مدعوم بالذكاء الاصطناعي يستخدم وكلاء مستقلين لإجراء التقييمات الأمنية. يدمج أكثر من 15 مزود ذكاء اصطناعي مع وكلاء اختبار أمني متخصصين لاكتشاف الثغرات الأمنية بشكل تلقائي.

## التثبيت

```bash
# التثبيت السريع
curl -fsSL https://cyberstrike.io/install | bash

# مديرو الحزم
npm i -g cyberstrike@latest        # أو bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS و Linux (موصى به)

# من المصدر
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### تطبيق سطح المكتب

متاح لأنظمة macOS و Windows و Linux. قم بالتنزيل من [صفحة الإصدارات](https://github.com/CyberStrikeus/cyberstrike.io/releases) أو [cyberstrike.io/download](https://cyberstrike.io/download).

| المنصة | التنزيل |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`، `.rpm`، أو AppImage              |

## وكلاء اختبار الاختراق

يتضمن CyberStrike 4 وكلاء متخصصين في اختبار الاختراق:

### web-application
اختبار أمن تطبيقات الويب باتباع منهجية OWASP/WSTG:
- تغطية OWASP Top 10 (A01-A10)
- أكثر من 120 حالة اختبار WSTG عبر 12 فئة
- اكتشاف حقن SQL، XSS، CSRF، XXE، SSTI
- اختبار أمن واجهات API (REST، GraphQL)
- تجاوز المصادقة والتفويض

### cloud-security
تقييم أمن البنية التحتية السحابية:
- AWS (IAM، S3، EC2، Lambda، RDS)
- Azure (AD، Blob Storage، RBAC، Key Vault)
- GCP (IAM، GCS، Compute، Cloud Functions)
- فحوصات امتثال معايير CIS Benchmark
- مسارات تصعيد الصلاحيات السحابية

### internal-network
متخصص في الشبكات الداخلية و Active Directory:
- تعداد الشبكة واكتشاف الخدمات
- هجمات AD (Kerberoasting، AS-REP Roasting)
- هجمات بيانات الاعتماد (Password Spraying، Pass-the-Hash)
- الحركة الجانبية (DCOM، WMI، PSExec)
- تصعيد الصلاحيات (Windows، Linux، Domain)

### bug-hunter
منهجية صيد المكافآت الأمنية:
- اكتشاف الأصول وتعداد النطاقات الفرعية
- تحليل البيانات التاريخية (Wayback، GAU)
- تحليل JavaScript لنقاط النهاية والأسرار
- تسلسل الثغرات الأمنية لتحقيق أقصى تأثير
- استراتيجيات المنصات (HackerOne، Bugcrowd)

## قاعدة المعرفة

قوائم فحص WSTG (دليل اختبار أمن الويب) المدمجة في `knowledge/web-application/`:

| الفئة | الاختبارات | الوصف |
|-------------|-------|------------------------|
| WSTG-INFO   | 10    | جمع المعلومات  |
| WSTG-CONF   | 13    | اختبار التكوين  |
| WSTG-IDNT   | 5     | إدارة الهوية    |
| WSTG-ATHN   | 11    | اختبار المصادقة |
| WSTG-AUTHZ  | 7     | اختبار التفويض  |
| WSTG-SESS   | 11    | إدارة الجلسات     |
| WSTG-INPV   | 29    | التحقق من المدخلات       |
| WSTG-ERRH   | 2     | معالجة الأخطاء         |
| WSTG-CRYP   | 4     | التشفير           |
| WSTG-BUSL   | 10    | منطق الأعمال         |
| WSTG-CLNT   | 14    | اختبار جانب العميل    |
| WSTG-APIT   | 4     | اختبار API            |

**الإجمالي: أكثر من 120 حالة اختبار تلقائية**

## الاستخدام

```bash
# بدء اختبار اختراق تطبيق ويب
cyberstrike --agent web-application
> "اختبر https://target.com للحقن SQL باتباع WSTG-INPV-05"

# تنفيذ الاستطلاع
cyberstrike --agent bug-hunter
> "عدد النطاقات الفرعية لـ target.com"

# تدقيق أمن السحابة
cyberstrike --agent cloud-security
> "دقق حساب AWS الخاص بي للتكوينات الخاطئة لـ S3 bucket"

# اختبار اختراق الشبكة الداخلية
cyberstrike --agent internal-network
> "قم بهجوم Kerberoasting على النطاق"
```

## تكامل الأدوات

يستفيد وكلاء CyberStrike من أدوات الأمان القياسية في الصناعة:

| الفئة   | الأدوات                                |
|------------|--------------------------------------|
| الشبكة    | nmap، masscan، netcat                |
| الويب        | nuclei، sqlmap، ffuf، nikto، burp    |
| السحابة      | prowler، scoutsuite، pacu            |
| AD/Windows | bloodhound، netexec، kerbrute        |
| الاستطلاع      | subfinder، amass، httpx، gau         |
| OSINT      | theHarvester، shodan، censys         |

### تكامل MCP Kali

يتضمن CyberStrike خادم MCP (`packages/mcp-kali`) مع الوصول إلى أكثر من 100 أداة من Kali Linux من خلال التحميل الديناميكي للأدوات، مما يوفر أكثر من 150 ألف رمز لكل جلسة.

## البنية

- **بيئة التشغيل**: Bun للتنفيذ السريع
- **اللغة**: TypeScript لسلامة الأنواع
- **واجهة المستخدم**: Solid.js + TUI لواجهة الطرفية
- **الذكاء الاصطناعي**: Vercel AI SDK مع دعم أكثر من 15 مزود (Anthropic، OpenAI، Google، Azure، AWS Bedrock، وأكثر)
- **MCP**: بروتوكول سياق النموذج للتكامل القابل للتوسيع للأدوات

## التوثيق

التوثيق الكامل متاح على [docs.cyberstrike.io](https://docs.cyberstrike.io).

## المساهمة

هل أنت مهتم بالمساهمة؟ يرجى قراءة [دليل المساهمة](./CONTRIBUTING.md) قبل تقديم طلب pull request.

## الترخيص

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">الموقع الإلكتروني</a> |
  <a href="https://docs.cyberstrike.io">التوثيق</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
