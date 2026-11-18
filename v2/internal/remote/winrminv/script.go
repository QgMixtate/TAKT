package winrminv

import _ "embed"

// Script — единственный сценарий, выполняемый на цели. Только чтение (Get-CimInstance, Get-ItemProperty),
// ничего не пишется на диск цели, нет пользовательских данных в тексте сценария. Вывод — один JSON-объект, только ASCII.
// Каждая ошибка источника фиксируется в errors как «источник:категория» (категория PowerShell не зависит от языка ОС),
// общий сбой — поле fatal. Сценарий не должен молчать. Совместим с Windows PowerShell 5.1.
//
//go:embed script.ps1
var Script string
