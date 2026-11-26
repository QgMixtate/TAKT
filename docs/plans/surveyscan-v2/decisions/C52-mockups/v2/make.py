#!/usr/bin/env python3
"""Макеты мастера portable, версия 2 (правки дизайна 1–5). Пишет HTML в C52-mockups/v2."""
from pathlib import Path

OUT = Path(__file__).resolve().parent

# иконки — штрих 1.75, 24×24 (в стиле lucide), рисуются inline
P = {
    'check': '<path d="M20 6 9 17l-5-5"/>',
    'lock': '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    'key': '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M17 6l3 3M14 9l2 2"/>',
    'clock': '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    'wrench': '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.5-.5-.5-2.5z"/>',
    'plug': '<path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0zM12 17v5"/>',
    'radar': '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 19 5"/>',
    'users': '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14a6 6 0 0 1 3.5 6"/>',
    'server': '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    'package': '<path d="m12 3 8.5 4.5v9L12 21l-8.5-4.5v-9z"/><path d="m3.5 7.5 8.5 4.5 8.5-4.5M12 12v9"/>',
    'usb': '<rect x="7" y="2" width="10" height="7" rx="1"/><path d="M5 9h14v7a5 5 0 0 1-5 5h-4a5 5 0 0 1-5-5z"/>',
    'shield': '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
    'alert': '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>',
    'x': '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>',
    'minus': '<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>',
    'okc': '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
    'pause': '<path d="M9 5v14M15 5v14"/>',
    'retry': '<path d="M3 12a9 9 0 0 1 15.5-6.2L21 8M21 3v5h-5M21 12a9 9 0 0 1-15.5 6.2L3 16M3 21v-5h5"/>',
    'copy': '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    'chev': '<path d="m9 6 6 6-6 6"/>',
    'left': '<path d="m15 6-6 6 6 6"/>',
    'grip': '<path d="M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01"/>',
    'plus': '<path d="M12 5v14M5 12h14"/>',
    'term': '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>',
    'win': '<path d="M3 5.5 10.5 4.5v7H3zM12 4.3 21 3v8.5h-9zM3 12.5h7.5v7L3 18.5zM12 12.5h9V21l-9-1.3z"/>',
}


def i(name, cls=''):
    return f'<svg class="ic {cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{P[name]}</svg>'


FONTS = ''.join(
    f"@font-face{{font-family:{fam};font-weight:{w};font-display:swap;src:url(fonts/{f}-{sub}-{w}-normal.woff2) format('woff2');unicode-range:{rng}}}"
    for fam, f, ws in (('Inter', 'inter', (400, 500, 600)), ('Manrope', 'manrope', (700,)))
    for w in ws
    for sub, rng in (('latin', 'U+0000-00FF,U+2000-206F,U+20AC,U+2116,U+2190-21FF,U+2212'), ('cyrillic', 'U+0400-045F,U+0490-0491,U+04B0-04B1'))
)

CSS = FONTS + '''
:root{--navy:#0F1A2B;--navy2:#17253B;--mag:#D6157A;--mag-d:#B8106A;--blue:#1E7BB0;--bg:#F3F5F9;--line:#E3E7EE;--line2:#EEF1F5;
--fg:#0F1A2B;--muted:#5B6678;--faint:#8A95A8;--ok:#1F8A4C;--warn:#B7791F;--bad:#C53030}
*{box-sizing:border-box}body{margin:0;font:400 13px/1.5 Inter,sans-serif;background:var(--bg);color:var(--fg);-webkit-font-smoothing:antialiased;font-feature-settings:"tnum" 1,"cv11" 1}
h1,h2,h3{font-family:Manrope,Inter,sans-serif;font-weight:700;letter-spacing:-.01em}
.ic{width:16px;height:16px;flex:none;vertical-align:-3px}
.app{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
aside{background:var(--navy);color:#C9D2E0;padding:20px 14px;display:flex;flex-direction:column;gap:20px}
.logo{display:flex;align-items:center;gap:10px;padding:0 6px}.mark{width:34px;height:34px;border:2px solid var(--mag);border-radius:9px;position:relative;display:grid;place-items:center;color:#fff;font:700 18px Manrope}.mark:after{content:"";position:absolute;top:5px;right:5px;width:6px;height:6px;border-radius:50%;background:var(--mag)}
.logo b{display:block;color:#fff;font:700 16px Manrope}.logo small{display:block;font-size:9.5px;letter-spacing:3px;color:#7F8DA4}
.grp{font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:#6F7E96;padding:0 8px}
.steps{display:flex;flex-direction:column;gap:2px}.st{display:flex;gap:10px;align-items:flex-start;padding:9px 8px;border-radius:8px}
.st .n{width:22px;height:22px;border-radius:50%;display:grid;place-items:center;font:600 11px Inter;border:1.5px solid #3A4A64;margin-top:1px}
.st.done .n{background:#1F8A4C;border-color:#1F8A4C;color:#fff}.st.done .n .ic{width:13px;height:13px;stroke-width:2.5}
.st.on{background:var(--navy2);color:#fff;box-shadow:inset 2px 0 0 var(--mag)}.st.on .n{border-color:var(--mag);color:#fff}
.st small{display:block;color:#7D8BA2;font-size:11.5px}
.media{margin-top:auto;padding:12px;border-top:1px solid #22324B;font-size:11.5px;color:#8D9AB0;display:flex;gap:10px}.media b{color:#E6EBF2;font-weight:500;display:block}
main{padding:20px 28px;display:flex;flex-direction:column;gap:16px;min-width:0}
.top{display:flex;align-items:center;gap:12px}.top h1{margin:0;font-size:21px}.sub{color:var(--muted);font-size:12.5px}.sp{flex:1}
.btn{display:inline-flex;align-items:center;gap:6px;height:34px;padding:0 14px;border-radius:8px;font:600 13px Inter;border:1px solid transparent;background:transparent;color:var(--fg);white-space:nowrap}
.btn.p{background:var(--mag);color:#fff;box-shadow:0 1px 2px rgba(214,21,122,.25)}.btn.s{background:#fff;border-color:var(--line)}.btn.g{color:var(--muted)}.btn.g:hover{background:#E9EDF3}
.card{background:#fff;border:1px solid var(--line);border-radius:12px}.ch{display:flex;align-items:center;gap:8px;padding:12px 16px;border-bottom:1px solid var(--line2)}.ch h3{margin:0;font-size:14px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);background:#fff;border:1px solid var(--line);border-radius:12px}
.kpi{padding:12px 16px;border-right:1px solid var(--line2);display:flex;flex-direction:column;gap:2px}.kpi:last-child{border:0}.kpi b{font:700 22px Manrope}.kpi span{color:var(--muted);font-size:12px;display:flex;gap:6px;align-items:center}.kpi.sel{box-shadow:inset 0 -2px 0 var(--mag)}
table{width:100%;border-collapse:collapse}th{font:600 11px Inter;color:var(--faint);text-align:left;padding:8px 12px;border-bottom:1px solid var(--line2);letter-spacing:.02em}
td{padding:0 12px;height:36px;border-bottom:1px solid var(--line2);white-space:nowrap}tr:last-child td{border-bottom:0}
.mono{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:12px}.muted{color:var(--muted)}.faint{color:var(--faint)}
.s-ok{color:var(--ok)}.s-warn{color:var(--warn)}.s-bad{color:var(--bad)}.s-n{color:var(--faint)}
.stt{display:inline-flex;align-items:center;gap:6px;font-weight:500}
.gh td{height:32px;background:#FAFBFC;font-weight:600;color:var(--fg)}.gh .ic{color:var(--muted)}
.prog{height:4px;background:#E8ECF2;border-radius:2px;overflow:hidden;width:88px;display:inline-block;vertical-align:middle}.prog i{display:block;height:100%;background:var(--blue)}
.log{font:12px/1.75 ui-monospace,Consolas,monospace;padding:10px 16px;color:#3A465A}.log .t{color:var(--faint);margin-right:8px}
.note{color:var(--muted);font-size:12.5px}
.chk{width:15px;height:15px;border-radius:4px;border:1.5px solid #B7C0CE;display:inline-grid;place-items:center;vertical-align:middle}.chk.on{background:var(--mag);border-color:var(--mag);color:#fff}.chk .ic{width:11px;height:11px;stroke-width:3}
'''


def page(name, cur, main, subs=None):
    titles = [('Подготовка', 'источник и ключ центра'), ('Обследование сети', '3 подсети · 412 узлов'), ('Профили учёток', '3 профиля · 4 правила'),
              ('Узлы и сбор', 'собрано 401 из 412'), ('Пакет', 'шифрование ключом центра')]
    subs = subs or {}
    items = []
    for n, (t, s) in enumerate(titles, 1):
        s = subs.get(n, s if n < cur else ('ещё не начато' if n > cur else s))
        cls = 'done' if n < cur else 'on' if n == cur else ''
        mark = i('check') if n < cur else str(n)
        items.append(f'<div class="st {cls}"><span class="n">{mark}</span><span>{t}<small>{s}</small></span></div>')
    side = f'''<aside><div class="logo"><div class="mark">т</div><div><b>такт</b><small>PORTABLE</small></div></div>
<div class="grp">Аудит площадки</div><div class="steps">{''.join(items)}</div>
<div class="media">{i('usb')}<div><b>E:\\audit-msk-01</b>свободно 14,2 ГБ · только 127.0.0.1</div></div></aside>'''
    html = f'<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Мастер portable — {name}</title><style>{CSS}</style></head><body><div class="app">{side}{main}</div></body></html>'
    (OUT / f'{name}.html').write_text(html)


# Шаг 1 — узкая колонка по центру
page('1-podgotovka', 1, f'''<main style="align-items:center;justify-content:center">
<div style="width:600px;display:flex;flex-direction:column;gap:16px">
<div><h1 style="margin:0 0 4px;font-size:24px">Подготовка носителя</h1><div class="sub">Шаг 1 из 5 · один раз на носитель</div></div>
<div class="card" style="padding:20px;display:flex;flex-direction:column;gap:14px">
<label style="font-weight:600">Строка подготовки из Web<div class="note" style="font-weight:400">«Portable-аудит» → «Новый носитель» → «Копировать строку»</div></label>
<div class="mono" style="border:1px solid var(--line);border-radius:8px;padding:10px 12px;height:76px;color:#3A465A;overflow:hidden;line-height:1.6;word-break:break-all">takt-portable:v1:eyJ0ZW5hbnQiOiIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzaXRlIjoiYzRmMmQ5…</div>
<div style="display:grid;grid-template-columns:auto 1fr;gap:8px 14px;font-size:13px">
<span class="s-ok stt">{i('okc')}</span><span>Площадка <b>Москва, ЦОД-1</b> · сетевая область <b>msk-dc1</b></span>
<span class="s-ok stt">{i('lock')}</span><span>Ключ шифрования центра получен · <span class="mono faint">X25519 8f3a…c21d</span></span>
<span class="faint stt">{i('usb')}</span><span>Каталог аудита <span class="mono">E:\\audit-msk-01</span></span></div>
<div style="display:flex;gap:8px;justify-content:flex-end;border-top:1px solid var(--line2);padding-top:14px"><button class="btn g">Выбрать другой каталог</button><button class="btn p">Подготовить носитель {i('chev')}</button></div></div>
<div class="note" style="display:flex;gap:10px;padding:0 4px">{i('shield')}<span>Ключ подписи создаётся на носителе и не покидает его. Пакет читает только центр. Пароли на диск не пишутся.</span></div>
</div></main>''')

# Шаг 3 — профили и правила без пустот
prof = [('term', 'linux-ro', 'SSH · ключ', 'audit', 'E:\\keys\\audit_ed25519', 'ok', '10.20.1.14 — вход выполнен', 181),
        ('win', 'win-domain', 'WinRM · текущая учётка Windows', 'CORP\\svc-audit', 'Kerberos, без пароля', 'ok', '10.20.1.11 — вход выполнен', 96),
        ('win', 'win-local', 'WinRM · пароль', '.\\auditor', 'пароль в памяти', 'bad', '10.20.1.63 — отказ: 401', 41)]
rows = ''.join(f'''<tr style="height:52px"><td style="width:36px;color:var(--muted)">{i(ic)}</td><td><b>{n}</b><div class="faint" style="font-size:12px">{k}</div></td>
<td class="mono">{u}<div class="faint" style="font:12px Inter">{sec}</div></td><td><span class="stt s-{"ok" if st=="ok" else "bad"}">{i("okc" if st=="ok" else "x")}{msg}</span></td><td style="text-align:right"><b>{c}</b> <span class="faint">узлов</span></td></tr>''' for ic, n, k, u, sec, st, msg, c in prof)
rules = [('Windows', 'любая', 'CORP', 'win-domain', 96), ('Windows', '10.20.6.0/24', '—', 'win-local', 41), ('Linux / SSH', 'любая', '—', 'linux-ro', 181), ('любой', '10.30.15.0/24', '—', 'не собирать', 0)]
rr = ''.join(f'<tr><td class="faint" style="width:30px">{i("grip")}</td><td class="faint">{n}</td><td>{a}</td><td class="mono">{b}</td><td>{c}</td><td><b>{d}</b></td><td style="text-align:right">{e}</td></tr>' for n, (a, b, c, d, e) in enumerate(rules, 1))
page('3-profili', 3, f'''<main>
<div class="top"><div><h1>Профили учёток</h1><div class="sub">Пароли держатся только в памяти мастера · перебора учёток нет</div></div><span class="sp"></span><button class="btn g">{i('plus')}Профиль</button><button class="btn p">Сохранить и дальше {i('chev')}</button></div>
<div style="display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:16px;align-items:start">
<div style="display:flex;flex-direction:column;gap:16px">
<div class="card"><div class="ch"><h3>Профили</h3><span class="sp"></span><span class="note">проверка — вход на одном узле</span></div><table>{rows}</table></div>
<div class="card"><div class="ch"><h3>Правила привязки</h3><span class="sp"></span><span class="note">сверху вниз, первое подходящее</span><button class="btn g" style="height:28px">{i('plus')}Правило</button></div>
<table><tr><th></th><th>№</th><th>Вид узла</th><th>Подсеть</th><th>Домен</th><th>Профиль</th><th style="text-align:right">Узлов</th></tr>{rr}</table></div>
<div class="card"><div class="ch"><h3>Без правила</h3><span class="s-warn stt" style="margin-left:4px">94</span><span class="sp"></span><span class="note">попадут в пакет как «найден, доступа нет»</span></div>
<table><tr><th>Группа</th><th>Пример</th><th style="text-align:right">Узлов</th><th></th></tr>
<tr><td>Сетевые устройства (SNMP не настроен)</td><td class="mono">10.20.1.52, 10.20.1.1</td><td style="text-align:right">25</td><td style="text-align:right"><button class="btn g" style="height:26px">{i('plus')}Правило</button></td></tr>
<tr><td>Windows вне домена CORP</td><td class="mono">10.30.4.18 (WORKGROUP)</td><td style="text-align:right">52</td><td style="text-align:right"><button class="btn g" style="height:26px">{i('plus')}Правило</button></td></tr>
<tr><td>Только веб-порты (80/443)</td><td class="mono">10.30.8.5</td><td style="text-align:right">17</td><td style="text-align:right"><button class="btn g" style="height:26px">{i('plus')}Правило</button></td></tr></table></div></div>
<div style="display:flex;flex-direction:column;gap:16px">
<div class="card" style="padding:16px"><h3 style="margin:0 0 10px;font-size:14px">Покрытие</h3>
<div style="display:flex;height:8px;border-radius:4px;overflow:hidden;margin-bottom:12px"><i style="flex:181;background:#1E7BB0"></i><i style="flex:96;background:#4A9BC9"></i><i style="flex:41;background:#8CC0DE"></i><i style="flex:94;background:#E3E7EE"></i></div>
<div style="display:grid;grid-template-columns:1fr auto;gap:6px;font-size:13px"><span class="muted">linux-ro</span><b>181</b><span class="muted">win-domain</span><b>96</b><span class="muted">win-local</span><b>41</b><span class="muted">без правила — «доступа нет»</span><b class="s-warn">94</b></div></div>
<div class="card" style="padding:16px"><div style="display:flex;gap:8px;align-items:center;margin-bottom:6px" class="s-bad">{i('lock')}<b>win-local не вошёл на 10.20.1.63</b></div>
<div class="note" style="margin-bottom:12px">WinRM ответил 401: неверный пароль или учётка .\\auditor отключена. Другие учётки мастер не пробует.</div>
<div style="display:flex;gap:6px"><button class="btn s">{i('key')}Ввести пароль заново</button><button class="btn g">Другой узел</button></div></div></div></div></main>''')

# Шаг 4 — сбор идёт: кнопки по весу, статусы текстом, светлый журнал
nodes = [('10.20.1.11', 'dc-msk-01', 'Windows', 'win-domain', 'ok', 'собрано', '12 / 12'), ('10.20.1.14', 'app-crm-02', 'Linux', 'linux-ro', 'ok', 'собрано', '12 / 12'),
         ('10.20.1.15', 'app-crm-03', 'Linux', 'linux-ro', 'run', 'сбор', ''), ('10.20.1.21', 'sql-01', 'Windows', 'win-domain', 'warn', 'частично', '11 / 12'),
         ('10.20.1.40', '—', 'Linux', 'linux-ro', 'bad', 'вход отклонён', '0 / 12'), ('10.20.1.52', '—', 'Сетевое', '—', 'n', 'доступа нет', ''),
         ('10.20.1.63', 'ws-buh-07', 'Windows', 'win-local', 'q', 'в очереди', ''), ('10.20.1.64', 'ws-buh-08', 'Windows', 'win-local', 'q', 'в очереди', '')]
ICON = {'ok': ('okc', 's-ok'), 'warn': ('alert', 's-warn'), 'bad': ('lock', 's-bad'), 'n': ('minus', 's-n'), 'q': ('clock', 's-n'), 'run': ('retry', '')}
nr = ''.join(f'''<tr><td style="width:34px"><span class="chk {'' if s=='n' else 'on'}">{'' if s=='n' else i('check')}</span></td><td class="mono">{a}</td><td>{h}</td><td class="muted">{k}</td><td class="muted">{p}</td>
<td><span class="stt {ICON[s][1]}">{i(ICON[s][0])}{t}</span></td><td>{'<span class="prog"><i style="width:58%"></i></span>' if s=='run' else f'<span class="muted">{r}</span>'}</td><td class="faint" style="width:24px">{i('chev') if s in ('warn','bad') else ''}</td></tr>''' for a, h, k, p, s, t, r in nodes)
page('4-sbor', 4, f'''<main>
<div class="top"><div><h1>Узлы и сбор</h1><div class="sub">Площадка «Москва, ЦОД-1» · шифрование ключом центра</div></div><span class="sp"></span><button class="btn g">{i('pause')}Пауза</button><button class="btn p">Собрать выбранные (318)</button></div>
<div class="kpis"><div class="kpi sel"><b>412</b><span>найдено</span></div><div class="kpi"><b>255</b><span class="s-ok">{i('okc')}собрано</span></div><div class="kpi"><b>17</b><span class="s-warn">{i('alert')}частично</span></div><div class="kpi"><b>11</b><span class="s-bad">{i('lock')}не вошли</span></div><div class="kpi"><b>94</b><span>{i('minus')}доступа нет</span></div></div>
<div style="display:grid;grid-template-columns:1fr 330px;gap:16px;align-items:start">
<div class="card"><div class="ch"><h3>Узлы</h3><span class="sp"></span><span class="note">выбрано 318 из 412</span></div>
<div style="display:flex;gap:8px;padding:10px 12px;border-bottom:1px solid var(--line2)"><div style="flex:1;border:1px solid var(--line);border-radius:8px;padding:6px 10px" class="mono">10.20.1.</div><button class="btn s" style="height:32px">Вид: все</button><button class="btn s" style="height:32px">Профиль: все</button><button class="btn s" style="height:32px">Итог: все</button></div>
<table><tr><th></th><th>Адрес</th><th>Имя</th><th>Вид</th><th>Профиль</th><th>Итог</th><th>Разделы</th><th></th></tr>{nr}</table></div>
<div class="card"><div class="ch"><h3>Ход сбора</h3><span class="sp"></span><span class="note">~6 мин</span></div>
<div style="padding:14px 16px 6px"><div style="height:6px;background:#E8ECF2;border-radius:3px;overflow:hidden"><i style="display:block;height:100%;width:62%;background:var(--blue)"></i></div>
<div style="display:flex;justify-content:space-between;margin-top:8px;font-size:12.5px"><span><b>255</b> <span class="muted">из 412</span></span><span class="muted">16 параллельно</span></div></div>
<div class="log"><div><span class="t">14:32:49</span><span class="s-warn">sql-01</span> 11 / 12 — нет прав: журналы</div><div><span class="t">14:32:47</span><span class="s-bad">10.20.1.40</span> вход отклонён</div><div><span class="t">14:32:44</span><span class="s-ok">app-crm-02</span> 12 / 12</div><div><span class="t">14:32:41</span><span class="s-ok">dc-msk-01</span> 12 / 12</div></div>
<div style="padding:10px 16px;border-top:1px solid var(--line2)"><button class="btn g" style="height:28px;padding:0 8px">{i('copy')}Копировать журнал</button></div></div></div></main>''', subs={4: 'идёт сбор 255 из 412'})

# Страница узла
secs = [('ОС', 'ok', 'Windows Server 2019 17763.6532'), ('Железо', 'ok', 'Dell R640 · 2× Xeon Gold 6230 · 256 ГБ'), ('Диски', 'ok', '4 тома · 3,6 ТБ'), ('Сеть', 'ok', '2 адаптера'),
        ('Программы', 'ok', '214 записей'), ('Обновления', 'ok', '37 KB · последнее 12.11'), ('Службы', 'ok', '186 служб'), ('Пользователи и группы', 'ok', 'Administrators: 4'),
        ('Журналы безопасности', 'bad', 'чтение журнала Security отклонено · 0x80070005'), ('Антивирус', 'ok', 'Defender · сигнатуры 25.11'), ('Открытые порты', 'ok', '14 портов'), ('Автозагрузка', 'ok', '9 записей')]
sr = ''.join(f'''<tr{' style="background:#FFF8F8"' if s=='bad' else ''}><td{' style="font-weight:600"' if s=='bad' else ''}>{n}</td><td><span class="stt {'s-ok' if s=='ok' else 's-bad'}">{i('okc' if s=='ok' else 'lock')}{'собрано' if s=='ok' else 'нет прав'}</span></td><td class="muted">{d}</td></tr>''' for n, s, d in secs)
chain = ''.join(f'<div style="display:flex;align-items:center;gap:6px" class="{c}">{i(ic)}<span style="color:var(--fg);white-space:nowrap">{t}</span></div>{"<span class=faint>—</span>" if k<4 else ""}' for k, (ic, c, t) in enumerate([('plug', 's-ok', 'порт 5985'), ('key', 's-ok', 'вход Kerberos'), ('shield', 's-ok', 'шифрование'), ('alert', 's-warn', 'сбор 11 / 12'), ('package', 's-ok', 'в пакете')]))
page('4-uzel', 4, f'''<main>
<div class="top"><div class="sub"><span style="color:var(--blue)">Узлы и сбор</span> › <span style="color:var(--blue)">Нет прав на раздел (15)</span> › sql-01</div><span class="sp"></span><button class="btn g">{i('left')}</button><span class="note">1 из 15</span><button class="btn g">{i('chev')}</button></div>
<div class="card" style="padding:18px 20px;display:flex;align-items:center;gap:24px"><div style="width:44px;height:44px;border-radius:10px;background:#EEF3F8;color:var(--blue);display:grid;place-items:center">{i('server')}</div>
<div style="flex:1"><h1 style="margin:0;font-size:22px">sql-01 <span class="faint" style="font-weight:600">10.20.1.21</span></h1><div class="sub">Windows Server 2019 · CORP · профиль win-domain (правило 1) · 26.11 14:32, 48 с</div>
<div style="display:flex;gap:12px;align-items:center;font-size:12.5px;margin-top:12px;padding-top:12px;border-top:1px solid var(--line2)">{chain}</div></div></div>
<div style="display:grid;grid-template-columns:1fr 400px;gap:16px;align-items:start">
<div class="card"><div class="ch"><h3>Разделы</h3><span class="sp"></span><span class="s-warn stt">{i('alert')}11 из 12</span></div><table><tr><th>Раздел</th><th>Итог</th><th>Подробно</th></tr>{sr}</table></div>
<div style="display:flex;flex-direction:column;gap:16px">
<div class="card" style="padding:18px">
<div class="s-bad" style="display:flex;gap:8px;align-items:center;font-weight:600;margin-bottom:6px">{i('lock')}Нет прав на журнал Security</div>
<div style="margin-bottom:14px">Учётке <span class="mono">CORP\\svc-audit</span> запрещено читать журнал. Остальные разделы в пакете; этот будет помечен «нет прав», а не «пусто».</div>
<div style="display:flex;gap:8px;align-items:center;font-weight:600;margin-bottom:6px;color:var(--blue)">{i('wrench')}Как исправить</div>
<div style="margin-bottom:16px">Добавить учётку в группу «Event Log Readers» на узле или через GPO, затем повторить. Та же причина — ещё на 14 узлах.</div>
<div style="display:flex;gap:8px"><button class="btn p">{i('retry')}Повторить узел</button><button class="btn s">Повторить все 15</button></div></div>
<div class="card"><div class="ch"><h3>Журнал узла</h3><span class="sp"></span><button class="btn g" style="height:26px;padding:0 6px">{i('copy')}</button></div>
<div class="log"><div><span class="t">14:32:01</span>подключение 10.20.1.21:5985 — <span class="s-ok">ok</span></div><div><span class="t">14:32:02</span>вход Kerberos CORP\\svc-audit — <span class="s-ok">ok</span></div><div><span class="t">14:32:41</span>security_log — <span class="s-bad">Access is denied (0x80070005)</span></div><div><span class="t"></span><span class="faint">code=SECTION_ACCESS_DENIED · попытка 1 из 1</span></div><div><span class="t">14:32:49</span>готово 11 / 12</div></div></div></div></div></main>''', subs={4: 'собрано 401 из 412'})
print('ok')
