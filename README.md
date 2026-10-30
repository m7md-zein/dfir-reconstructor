# DFIR Reconstructor

إعادة بناء سلسلة الهجوم من لوجات متعددة المصادر (مشروع ورك بيز).

## الحالة
- [x] Sysmon parser + normalizer + entity resolution (Muhammad)
- [ ] Attack graph + correlation
- [ ] Detection rules + scoring + gap detection
- [ ] Linux auth parser + evaluator + viewer

## ابدأ من هنا
1. اقرا `docs/schema.md` (شكل الأحداث والكيانات)
2. شوف العيّنة في `sample/` (25 حدث جاهزين)
3. للتشغيل: `pip install -r requirements.txt` ثم `pytest -q`

## قواعد الشغل
- branch لكل واحد، وPull Request للدمج
- ممنوع رفع ملفات `.evtx` أو لوجات حساسة
