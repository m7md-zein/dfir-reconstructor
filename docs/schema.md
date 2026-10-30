# Unified Event Schema (Sysmon side)

كل حدث = سطر JSON واحد في `events.jsonl` (ونفس البيانات في `events.parquet`).

## الحقول

| Field | Meaning |
|---|---|
| timestamp_utc | وقت الحدث UTC، صيغة ISO 8601 ثابتة (6 أرقام كسور) |
| host | اسم الجهاز |
| event_id | رقم حدث Sysmon (1, 3, 10, 11, 13) |
| event_type | process_create / network_connect / process_access / file_create / registry_set |
| user | اليوزر (DOMAIN\name). موجود في الأحداث 1 و3 بس |
| logon_id | رقم الجلسة، صيغة hex مختصرة (0x391e334) |
| process_guid | مفتاح العملية الفاعلة. هو المرجع الأساسي |
| process_name | مسار الملف التنفيذي للعملية |
| pid | رقم العملية (بيتكرر، متعتمدش عليه كمفتاح) |
| cmdline | سطر الأوامر |
| parent_guid / parent_name / parent_cmdline | الأب (في process_create بس) |
| src_ip / src_port / dst_ip / dst_port | بيانات الاتصال (network_connect بس) |
| target | الهدف: GUID العملية (process_access) أو مسار الملف (file_create) أو مفتاح Registry (registry_set) |
| raw_ref | `اسم_الملف#رقم_السجل`، بيربط الحدث بالسطر الأصلي |
| source | مصدر اللوج (sysmon) |
| extra | حقول إضافية حسب النوع (hashes, granted_access, details, rule_name...) |

القيمة `null` معناها: الحقل مش موجود في الحدث الأصلي.

## قواعد لازم تتفهم

1. **الـ GUID هو المرجع، والاسم معلومة مساعدة.** لو نفس الـ GUID ظهر بأسماء مختلفة، بيتسجّل في `name_conflicts` في `processes.json`.
2. **عملية من غير حدث إنشاء** (`has_create_event = false`): غالبًا عملية نظام اشتغلت قبل بداية التسجيل. ده دليل ناقص (مفيد لـ Gap Detection)، مش خطأ.
3. **اليوزر `null`** في عملية معناه إننا ما شفناش حدث إنشاء ليها، ومش بنخمّن قيمة.
4. **الجلسة** = `host|logon_id` (الـ LogonId بيتكرر بين الأجهزة).
5. الأحداث المرفوضة في validation بتتكتب في `rejects.jsonl` مع السبب، ومبتتمسحش بصمت.

## الملفات الناتجة (`python src/build_all.py <evtx_folder> output`)

| File | Content |
|---|---|
| events.jsonl / events.parquet | الأحداث الموحدة، مرتبة بالوقت |
| relations.jsonl | علاقات: spawned / accessed / connected_to / created_file / set_registry |
| processes.json | جدول العمليات (مفتاحه process_guid) |
| entities_other.json | Hosts, Users, Sessions, IPs |
| manifest.json | لكل ملف لوج: SHA-256 وعدد السجلات والتالف |
| rejects.jsonl | الأحداث المرفوضة وأسبابها |

## التشغيل

    pip install -r requirements.txt
    pytest -q
    python src/build_all.py <مجلد EVTX> output
    python src/make_sample.py

عيّنة صغيرة جاهزة في `sample/` (25 حدث من EVTX-ATTACK-SAMPLES، ريبو عام).