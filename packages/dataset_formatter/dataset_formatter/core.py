import json

def format_summary(records: list) -> str:
    """Aggregates and formats research dataset records into a markdown report."""
    total_records = len(records)
    lines = [
        "# Research Dataset Summary Report",
        f"**Total Records Processed:** {total_records}",
        "",
        "| Record ID | Title | Value |",
        "| :--- | :--- | :--- |"
    ]
    for r in records:
        lines.append(f"| {r.get('id', 'N/A')} | {r.get('title', 'N/A')} | {r.get('value', 'N/A')} |")
    return "\n".join(lines)