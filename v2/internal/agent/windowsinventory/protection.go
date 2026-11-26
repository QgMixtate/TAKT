package windowsinventory

// uniqueAntivirus — ISSUES №122: SecurityCenter2 хранит несколько регистраций одного антивируса (после обновлений —
// одинаковый displayName, разный productState). Ключ записи раздела protection в центре — kind+provider+name, дубль
// отклоняет всё наблюдение. Оставляется первая регистрация каждого имени (порядок WMI), остальные отбрасываются.
func uniqueAntivirus(rows []map[string]any) []map[string]any {
	seen := map[string]bool{}
	out := rows[:0:0]
	for _, row := range rows {
		name, _ := row["name"].(string)
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, row)
	}
	return out
}
