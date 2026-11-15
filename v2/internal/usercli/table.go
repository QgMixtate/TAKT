package usercli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"
)

func safeCell(v any) string {
	if v == nil {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, fmt.Sprint(v))
}
func render(w io.Writer, raw []byte, operation, format string) error {
	if format == "json" {
		_, e := fmt.Fprintln(w, string(raw))
		return e
	}
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		return fail(5, "INVALID_RESPONSE")
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	write := func(values ...any) {
		cells := make([]string, len(values))
		for i, v := range values {
			cells[i] = safeCell(v)
		}
		fmt.Fprintln(table, strings.Join(cells, "\t"))
	}
	switch {
	case strings.HasPrefix(operation, "assets "):
		write("ASSET_UID", "HOSTNAME", "FRESHNESS")
		items, _ := object["items"].([]any)
		if !strings.HasSuffix(operation, "list") {
			items = []any{object}
		}
		for _, item := range items {
			if row, ok := item.(map[string]any); ok {
				write(row["asset_uid"], row["observed_hostname"], row["freshness"])
			}
		}
	case strings.HasPrefix(operation, "sources "):
		write("SOURCE_ID", "KIND", "STATE", "LAST_CONTACT", "LAST_INVENTORY")
		items, _ := object["items"].([]any)
		if !strings.HasSuffix(operation, "list") {
			items = []any{object}
		}
		for _, item := range items {
			if row, ok := item.(map[string]any); ok {
				write(row["source_id"], row["source_kind"], row["state"], row["last_contact_at"], row["last_successful_inventory_at"])
			}
		}
	case operation == "warehouse units":
		write("UNIT_ID", "ITEM", "SERIAL", "INVENTORY_NO", "STATE", "LOCATION_ID", "HOLDER_ID", "ASSET_UID")
		items, _ := object["items"].([]any)
		for _, item := range items {
			if row, ok := item.(map[string]any); ok {
				write(row["unit_id"], row["item_name"], row["serial"], row["inventory_no"], row["state"], row["location_id"], row["holder_id"], row["asset_uid"])
			}
		}
	case operation == "warehouse stock":
		write("ITEM", "LOCATION_ID", "QUANTITY", "RESERVED", "UNIT")
		items, _ := object["items"].([]any)
		for _, item := range items {
			if row, ok := item.(map[string]any); ok {
				write(row["item_name"], row["location_id"], row["quantity"], row["reserved"], row["unit"])
			}
		}
	case operation == "warehouse movements", operation == "warehouse act", operation == "warehouse move":
		write("ACT_NO", "KIND", "OCCURRED_AT", "BASIS", "MOVEMENT_ID")
		items, _ := object["items"].([]any)
		if operation != "warehouse movements" {
			items = []any{object}
		}
		for _, item := range items {
			if row, ok := item.(map[string]any); ok {
				write(row["act_no"], row["kind"], row["occurred_at"], row["basis"], row["movement_id"])
			}
		}
	case operation == "warehouse verify":
		write("ITEM_ID", "LOCATION_ID", "STOCK", "JOURNAL")
		items, _ := object["discrepancies"].([]any)
		for _, item := range items {
			if row, ok := item.(map[string]any); ok {
				write(row["item_id"], row["location_id"], row["stock"], row["journal"])
			}
		}
	case strings.HasPrefix(operation, "profiles "):
		config, _ := object["config"].(map[string]any)
		write("SOURCE_ID", "DESIRED", "APPLIED", "HEARTBEAT_SECONDS", "INVENTORY_SECONDS")
		write(object["source_id"], config["profile_revision"], object["applied_revision"], config["heartbeat_seconds"], config["inventory_seconds"])
	case operation == "diagnostics":
		write("ALERT", "SEVERITY", "SOURCE_ID")
		alerts, _ := object["alerts"].([]any)
		for _, item := range alerts {
			if row, ok := item.(map[string]any); ok {
				write(row["code"], row["severity"], row["source_id"])
			}
		}
	case operation == "status":
		write("STATUS")
		write(object["status"])
	default:
		return fail(2, "TABLE_OUTPUT_NOT_SUPPORTED_FOR_COMMAND")
	}
	if cursor, ok := object["next_cursor"].(string); ok {
		write("NEXT_CURSOR", cursor)
	}
	return table.Flush()
}
