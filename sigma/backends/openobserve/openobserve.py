"""OpenObserve backend for pySigma"""

# pylint: disable=line-too-long,fixme,invalid-name
import re
import json
from typing import ClassVar, Dict, List, Optional, Pattern, Tuple, Union, Any

from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionValueExpression,
    ConditionFieldEqualsValueExpression,
)
from sigma.types import (
    SigmaCompareExpression,
    SigmaString,
    SpecialChars,
    # SigmaRegularExpressionFlag,
    SigmaCIDRExpression,
)


class openobserveBackend(TextQueryBackend):
    """OpenObserve backend."""

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name: ClassVar[str] = "OpenObserve backend"
    formats: Dict[str, str] = {
        "default": "Plain SQL queries (OpenObserve/Apache Datafusion)",
        "o2alert": "OpenObserve JSON alerts",
    }
    requires_pipeline: bool = (
        False  # TODO: does the backend requires that a processing pipeline is provided? This information can be used by user interface programs like Sigma CLI to warn users about inappropriate usage of the backend.
    )

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    parenthesize: bool = True
    group_expression: ClassVar[str] = (
        "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder
    )

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = (
        "="  # Token inserted between field and value (without separator)
    )

    # String output
    ## Fields
    ### Quoting

    # FIXME! unclear if tick is valid quote for Apache Datafusion
    # => double quote works in openobserve but not single quote or tick.
    field_quote: ClassVar[str] = (
        '"'  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    )
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^[a-zA-Z0-9_]*$"
    )  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    )

    ## Values
    str_quote: ClassVar[str] = (
        "'"  # string quoting character (added as escaping character)
    )

    escape_char: ClassVar[str] = (
        # "\\"  # Escaping character for special characters inside string
        ""
    )
    wildcard_multi: ClassVar[str] = "%"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "_"  # Character used as single-character wildcard

    # Special case for case sensitive string matching
    wildcard_glob: ClassVar[str] = "*"  # Character used as glob wildcard
    wildcard_glob_single: ClassVar[str] = "?"  # Character used as glob wildcard

    # FIXME! https://datafusion.apache.org/user-guide/sql/operators.html#escaping
    #   E'string_to_escape'
    add_escaped: ClassVar[str] = (
        # "\\"  # Characters quoted in addition to wildcards and string quote
        ""
    )
    # filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = (
        {  # Values to which boolean values are mapped.
            True: "true",
            False: "false",
        }
    )

    # String matching operators. if none is appropriate eq_token is used.
    # FIXME! OpenObserve identifies ESCAPE as operator but triggers execution error
    # "Error during planning: Invalid escape character in LIKE expression"
    startswith_expression: ClassVar[str] = "{field} LIKE '{value}%'"
    endswith_expression: ClassVar[str] = "{field} LIKE '%{value}'"
    contains_expression: ClassVar[str] = "{field} LIKE '%{value}%'"
    wildcard_match_expression: ClassVar[str] = (
        # "{field} LIKE '{value}' ESCAPE '\\'"  # Special expression if wildcards can't be matched with the eq_token operator
        "{field} LIKE '{value}'"
    )

    field_exists_expression: ClassVar[str] = "{field} = {field}"

    # Special expression if wildcards can't be matched with the eq_token operator
    # wildcard_match_str_expression: ClassVar[str] = "{field} LIKE '{value}' ESCAPE '\\'"
    wildcard_match_str_expression: ClassVar[str] = "{field} LIKE '{value}'"
    # wildcard_match_num_expression: ClassVar[str] = "{field} LIKE '%{value}%'"

    # Regular expressions
    # https://datafusion.apache.org/user-guide/sql/scalar_functions.html#regular-expression-functions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    # Empty flag string will make openobserve error.
    # re_expression: ClassVar[str] = "regexp_like({field}, '{regex}', '{flag_i}')"
    re_expression: ClassVar[str] = "regexp_like({field}, '{regex}', 'i')"
    re_escape_char: ClassVar[str] = (
        ""  # Character used for escaping in regular expressions
    )
    re_escape: ClassVar[Tuple[str]] = ()  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped
    re_flag_prefix: bool = (
        True  # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    )

    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    # re_flags : Dict[SigmaRegularExpressionFlag, str] = {}

    # https://datafusion.apache.org/user-guide/sql/scalar_functions.html#contains
    case_sensitive_match_expression: ClassVar[str] = "contains({field}, {value})"

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = (
        "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[Optional[str]] = (
        None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    )
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (
        True,
        True,
    )  # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    # https://datafusion.apache.org/user-guide/sql/scalar_functions.html#nvl2
    field_null_expression: ClassVar[str] = (
        "nvl2({field}, true, false)"  # Expression for field has null value as format string with {field} placeholder for field name
    )

    # Field existence condition expressions.
    # field_exists_expression : ClassVar[str] = "exists({field})"             # Expression for field existence as format string with {field} placeholder for field name
    # field_not_exists_expression : ClassVar[str] = "notexists({field})"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = False  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        False  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )
    field_in_list_expression: ClassVar[str] = (
        "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[str] = (
        "IN"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    # and_in_operator : ClassVar[str] = "contains-all"   # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field

    # TODO : SQlite only handles FTS ("MATCH") with virtual tables. Not Handled for now.
    # unbound_value_str_expression : ClassVar[str] = "MATCH {value}"   # Expression for string value not bound to a field as format string with placeholder {value}
    # unbound_value_num_expression : ClassVar[str] = 'MATCH {value}'     # Expression for number value not bound to a field as format string with placeholder {value}

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = (
        ""  # String used as separator between main query and deferred parts
    )
    deferred_separator: ClassVar[str] = (
        ""  # String used to join multiple deferred query parts
    )
    deferred_only_query: ClassVar[str] = (
        ""  # String used as query if final query only contains deferred expression
    )

    table = "<TABLE_NAME>"

    def convert_value_str(
        self,
        s: SigmaString,
        state: ConversionState,
        no_quote: bool = False,
        glob_wildcards: bool = False,
    ) -> str:
        """Convert a SigmaString into a plain string which can be used in query."""

        if glob_wildcards:
            converted = s.convert(
                escape_char=self.escape_char,
                wildcard_multi=self.wildcard_glob,
                wildcard_single=self.wildcard_glob_single,
                add_escaped=self.add_escaped,
                filter_chars=self.filter_chars,
            )
        else:
            converted = s.convert(
                escape_char=self.escape_char,
                wildcard_multi=self.wildcard_multi,
                wildcard_single=self.wildcard_single,
                add_escaped=self.add_escaped,
                filter_chars=self.filter_chars,
            )

        converted = converted.replace(
            "'", "''"
        )  # Doubling single quote in SQL is mandatory

        if self.decide_string_quoting(s) and not no_quote:
            return self.quote_string(converted)

        return converted

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        try:
            remove_quote = True  # Expressions that use "LIKE" (starswith, endswith, ...) don't need supplemental quotes

            if (  # Check conditions for usage of 'startswith' operator
                self.startswith_expression
                is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(
                    SpecialChars.WILDCARD_MULTI
                )  # String ends with wildcard
                and not cond.value[
                    :-1
                ].contains_special()  # Remainder of string doesn't contains special characters
            ):
                expr = (
                    self.startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operartor instead of equal token
                value = cond.value[:-1]
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
            ):
                expr = self.endswith_expression
                value = cond.value[1:]
            elif (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
            ):
                expr = self.contains_expression
                value = cond.value[1:-1]
            elif (  # wildcard match expression: string contains wildcard
                self.wildcard_match_expression is not None
                and (
                    cond.value.contains_special()
                    or self.wildcard_multi in cond.value
                    or self.wildcard_single in cond.value
                    or self.escape_char in cond.value
                )
            ):
                expr = self.wildcard_match_expression
                value = cond.value
            else:
                expr = "{field}" + self.eq_token + "{value}"
                value = cond.value
                remove_quote = False

            if remove_quote:
                return expr.format(
                    field=self.escape_and_quote_field(cond.field),
                    value=self.convert_value_str(value, state, remove_quote),
                )

            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state),
            )
        except TypeError as exc:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            ) from exc

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of case-sensitive field = string value expressions"""
        try:
            if (  # Check conditions for usage of 'startswith' operator
                self.case_sensitive_startswith_expression
                is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(
                    SpecialChars.WILDCARD_MULTI
                )  # String ends with wildcard
                and (
                    self.case_sensitive_startswith_expression_allow_special
                    or not cond.value[:-1].contains_special()
                )  # Remainder of string doesn't contains special characters or it's allowed
            ):
                expr = (
                    self.case_sensitive_startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operator instead of equal token
                value = cond.value[:-1]
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.case_sensitive_endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.case_sensitive_endswith_expression_allow_special
                    or not cond.value[1:].contains_special()
                )
            ):
                expr = self.case_sensitive_endswith_expression
                value = cond.value[1:]
            elif (  # contains: string starts and ends with wildcard
                self.case_sensitive_contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.case_sensitive_contains_expression_allow_special
                    or not cond.value[1:-1].contains_special()
                )
            ):
                expr = self.case_sensitive_contains_expression
                value = cond.value[1:-1]
            elif self.case_sensitive_match_expression is not None:
                expr = self.case_sensitive_match_expression
                value = cond.value
            else:
                raise NotImplementedError(
                    "Case-sensitive string matching is not supported by backend."
                )

            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(
                    value, state, no_quote=False, glob_wildcards=True
                ),
                regex=self.convert_value_re(value.to_regex(self.add_escaped_re), state),
            )
        except TypeError as exc:  # pragma: no cover
            raise NotImplementedError(
                "Case-sensitive field equals string value expressions with strings are not supported by the backend."
            ) from exc

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches CIDR value expressions."""
        cidr: SigmaCIDRExpression = cond.value
        expanded = cidr.expand()
        expanded_cond = ConditionOR(
            [
                ConditionFieldEqualsValueExpression(cond.field, SigmaString(network))
                for network in expanded
            ],
            cond.source,
        )
        return self.convert_condition(expanded_cond, state)

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Any:

        # TODO : fields support will be handled with a backend option (all fields by default)
        # fields = "*" if len(rule.fields) == 0 else f"*, {', '.join(rule.fields)}"

        # TODO : table name will be handled with a backend option
        o2_query = f"SELECT * FROM {self.table} WHERE {query}"

        return o2_query

    # pylint: disable=unused-argument
    def finalize_query_o2alert(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Any:
        """Finalize query in o2alert format."""

        o2_query = f'SELECT * FROM "{self.table}" WHERE {query}'
        rule_as_dict = rule.to_dict()

        o2_alert_rule = {
            "id": rule_as_dict["id"] if "id" in rule_as_dict else "",
            "name": rule_as_dict["title"],
            "org_id": "default",
            "stream_type": "logs",
            "stream_name": self.table,
            "is_real_time": False,
            "query_condition": {
                "type": "sql",
                "conditions": [],
                "sql": o2_query,
                "multi_time_range": [],
            },
            "trigger_condition": {
                "period": 60,
                "operator": ">=",
                "threshold": 3,
                "frequency": 60,
                "cron": "",
                "frequency_type": "minutes",
                "silence": 240,
                "timezone": "UTC",
            },
            "destinations": ["<alert-destination-TBD>"],
            "context_attributes": {},
            "row_template": "",
            "description": (
                (rule_as_dict["description"] if "description" in rule_as_dict else "")
                + "\nlevel: "
                + (rule_as_dict["level"] if "level" in rule_as_dict else "")
                + "\nstatus: "
                + (rule_as_dict["status"] if "status" in rule_as_dict else "")
                + "\nauthor: "
                + (rule_as_dict["author"] if "author" in rule_as_dict else "")
            ),
            "enabled": True,
            "tz_offset": 0,
            "owner": "<alert-owner-TBD>",
        }
        return o2_alert_rule

    def finalize_output_o2alert(self, queries: List[Dict]) -> str:
        """Finalize output in o2alert format."""
        return json.dumps(list(queries))

    # TODO : Full Text Search with match_all('v')
    # https://openobserve.ai/docs/sql_reference/#match_allv
    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only strings."""
        raise SigmaFeatureNotSupportedByBackendError(
            "Value-only string expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
        )

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only numbers."""
        raise SigmaFeatureNotSupportedByBackendError(
            "Value-only number expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
        )
