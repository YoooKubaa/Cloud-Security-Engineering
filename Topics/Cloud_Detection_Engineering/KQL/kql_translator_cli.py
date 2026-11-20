# --- IMPORTS (LIBRARIES AND MODULES) ---
import argparse  # (dev) Standard Python library for parsing CLI arguments.
import json      # (dev) Library for structuring and exporting translation reports.
import re        # (dev) Regular expressions for parsing KQL pipe operators and expressions.
import sys       # (dev) Provides system-level functions for exit codes and error logs.
from pathlib import Path  # (dev) Modern, object-oriented filesystem path manipulation.


class KQLToAWSTranslator:
    """
    (dev) Translates pipe-based Kusto Query Language (KQL) detection rules
    into AWS CloudWatch Logs Insights and Amazon Athena SQL queries.
    """

    # Cross-cloud schema field normalization map (Azure Sentinel -> AWS CloudTrail)
    FIELD_MAP = {
        "UserPrincipalName": "userIdentity.arn",
        "UserIdentityArn": "userIdentity.arn",
        "IPAddress": "sourceIPAddress",
        "SourceIPAddress": "sourceIPAddress",
        "ResultType": "errorCode",
        "ErrorCode": "errorCode",
        "EventName": "eventName",
        "TimeGenerated": "@timestamp",
    }

    def _map_field(self, field_name):
        """
        (dev) Maps an Azure/generic KQL column name to its AWS CloudTrail equivalent.
        """
        cleaned = field_name.strip()
        return self.FIELD_MAP.get(cleaned, cleaned)

    def _normalize_condition(self, expr):
        """
        (dev) Converts KQL comparison syntax (e.g., Col == "val") into CloudWatch and SQL syntax.
        """
        match = re.match(r'^([A-Za-z0-9_.]+)\s*(==|!=|>=|<=|>|<)\s*(.+)$', expr.strip())
        if not match:
            return expr.strip(), expr.strip()

        raw_col, op, raw_val = match.groups()
        aws_col = self._map_field(raw_col)
        sql_col = aws_col.lower()

        val_clean = raw_val.strip().strip('"').strip("'")
        is_numeric = val_clean.isdigit()

        cw_op = "=" if op == "==" else op
        sql_op = "=" if op == "==" else op

        cw_val = val_clean if is_numeric else f"'{val_clean}'"
        sql_val = val_clean if is_numeric else f"'{val_clean}'"

        return f"{aws_col} {cw_op} {cw_val}", f"{sql_col} {sql_op} {sql_val}"

    def translate(self, kql_query):
        """
        (dev) Parses a pipe-delimited KQL query and generates AWS CloudWatch Logs Insights
        and Amazon Athena SQL equivalents.
        """
        stages = [stage.strip() for stage in kql_query.split("|") if stage.strip()]
        if not stages:
            raise ValueError("Empty KQL query provided.")

        source_table = stages[0]
        cw_filters = []
        sql_where = []
        sql_having = []
        projected_fields = []
        group_by_fields = []
        count_alias = None

        for stage in stages[1:]:
            lower_stage = stage.lower()

            if lower_stage.startswith("where "):
                condition = stage[6:].strip()
                # Check if condition references an aggregation alias (e.g., FailedAttempts > 5)
                if count_alias and condition.startswith(count_alias):
                    cw_filters.append(condition)
                    having_expr = condition.replace(count_alias, "COUNT(*)", 1)
                    sql_having.append(having_expr)
                else:
                    cw_cond, sql_cond = self._normalize_condition(condition)
                    cw_filters.append(cw_cond)
                    sql_where.append(sql_cond)

            elif lower_stage.startswith("project "):
                cols = [self._map_field(c) for c in stage[8:].split(",")]
                projected_fields.extend(cols)

            elif lower_stage.startswith("summarize "):
                # Pattern: summarize Alias=count() by Col1, Col2
                sum_match = re.match(
                    r'^summarize\s+(?:([A-Za-z0-9_]+)\s*=\s*)?count\(\)\s+by\s+(.+)$',
                    stage,
                    re.IGNORECASE,
                )
                if sum_match:
                    count_alias = sum_match.group(1) or "event_count"
                    raw_groups = sum_match.group(2).split(",")
                    group_by_fields = [self._map_field(g) for g in raw_groups]

        # Build CloudWatch Logs Insights query
        cw_parts = []
        if projected_fields:
            cw_parts.append(f"fields @timestamp, {', '.join(projected_fields)}")
        elif group_by_fields:
            cw_parts.append(f"fields @timestamp, {', '.join(group_by_fields)}")
        else:
            cw_parts.append("fields @timestamp, eventName, userIdentity.arn, sourceIPAddress")

        # Separate pre-aggregation filters from post-aggregation filters
        pre_agg_filters = [f for f in cw_filters if not (count_alias and f.startswith(count_alias))]
        post_agg_filters = [f for f in cw_filters if (count_alias and f.startswith(count_alias))]

        if pre_agg_filters:
            cw_parts.append(f"filter {' and '.join(pre_agg_filters)}")

        if group_by_fields:
            cw_parts.append(f"stats count(*) as {count_alias} by {', '.join(group_by_fields)}")

        if post_agg_filters:
            cw_parts.append(f"filter {' and '.join(post_agg_filters)}")

        cw_query = " | ".join(cw_parts)

        # Build Amazon Athena SQL query
        athena_table = "cloudtrail_logs"
        if group_by_fields:
            sql_group_cols = [c.lower() for c in group_by_fields]
            select_clause = f"SELECT {', '.join(sql_group_cols)}, COUNT(*) AS {count_alias}"
        elif projected_fields:
            select_clause = f"SELECT {', '.join(c.lower() for c in projected_fields)}"
        else:
            select_clause = "SELECT eventtime, eventname, useridentity.arn, sourceipaddress"

        sql_parts = [f"{select_clause} FROM {athena_table}"]
        if sql_where:
            sql_parts.append(f"WHERE {' AND '.join(sql_where)}")
        if group_by_fields:
            sql_parts.append(f"GROUP BY {', '.join(c.lower() for c in group_by_fields)}")
        if sql_having:
            sql_parts.append(f"HAVING {' AND '.join(sql_having)}")

        athena_query = " ".join(sql_parts) + ";"

        return {
            "source_table": source_table,
            "original_kql": kql_query,
            "cloudwatch_logs_insights": cw_query,
            "amazon_athena_sql": athena_query,
        }


# --- MOCK DATA GENERATOR ---
def get_mock_kql_query():
    """
    (dev) Returns a classic KQL brute-force / failed login detection query for demonstration.
    """
    return (
        'SigninLogs | where ResultType != "0" '
        '| summarize FailedAttempts=count() by UserPrincipalName, IPAddress '
        '| where FailedAttempts > 5'
    )


# --- MAIN CLI LOGIC (ARGPARSE) ---
def main():
    """
    (dev) CLI entry point. Parses KQL query input, translates it to AWS dialects,
    and exports structured JSON output.
    """
    parser = argparse.ArgumentParser(
        description="KQL-to-AWS-Translator: Converts Azure KQL pipe queries into AWS Logs Insights & Athena SQL."
    )

    parser.add_argument('action', choices=['translate'], help="Action to execute ('translate')")
    parser.add_argument('--query', type=str, help="Raw KQL query string to translate", default=None)
    parser.add_argument('--output', type=str, help="File path to save JSON translation output", default=None)
    parser.add_argument('--mock', action='store_true', help="Run translator with built-in mock KQL brute-force query")

    args = parser.parse_args()

    if args.action == 'translate':
        if args.mock:
            print("[*] MOCK mode active. Translating sample Sentinel KQL brute-force rule to AWS...")
            kql_input = get_mock_kql_query()
        elif args.query:
            kql_input = args.query
        else:
            print("[!] Error: Provide --query '<KQL>' or use --mock.", file=sys.stderr)
            sys.exit(1)

        translator = KQLToAWSTranslator()
        try:
            translation_result = translator.translate(kql_input)
        except ValueError as err:
            print(f"[!] Translation Error: {err}", file=sys.stderr)
            sys.exit(1)

        report = {
            "metadata": {
                "philosophy": (
                    "Multi-Cloud Detection Portability: Translate Azure Sentinel KQL pipe queries "
                    "into AWS CloudWatch Logs Insights and Athena SQL to reuse cross-platform threat hunting logic."
                ),
                "source_dialect": "KQL (Kusto Query Language)",
                "target_dialects": ["AWS CloudWatch Logs Insights", "Amazon Athena SQL"],
            },
            "translation": translation_result,
        }

        json_output = json.dumps(report, indent=4)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_output, encoding='utf-8')
            print(f"[+] Translation report saved to: {output_path.absolute()}")
        else:
            print(json_output)

        sys.exit(0)


if __name__ == "__main__":
    main()