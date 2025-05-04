"""OpenObserve backend for pySigma Tests"""

# pylint: disable=line-too-long,fixme,invalid-name,missing-function-docstring,redefined-outer-name
import pytest
from sigma.collection import SigmaCollection
from sigma.backends.openobserve import openobserveBackend


@pytest.fixture
def openobserve_backend():
    return openobserveBackend()


# TODO: implement tests for some basic queries and their expected results.
def test_openobserve_and_expression(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' AND fieldB='valueB'"]
    )


def test_openobserve_or_expression(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' OR fieldB='valueB'"]
    )


def test_openobserve_and_or_expression(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE (fieldA='valueA1' OR fieldA='valueA2') AND (fieldB='valueB1' OR fieldB='valueB2')"
        ]
    )


def test_openobserve_or_and_expression(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE (fieldA='valueA1' AND fieldB='valueB1') OR (fieldA='valueA2' AND fieldB='valueB2')"
        ]
    )


def test_openobserve_in_expression(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' OR fieldA='valueB' OR fieldA LIKE 'valueC%'"
        ]
    )


def test_openobserve_regex_query(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE regexp_match(fieldA, 'foo.*bar', '') AND fieldB='foo'"
        ]
    )


def test_openobserve_cidr_query(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE field LIKE '192.168.%'"]
    )


def test_openobserve_field_name_with_whitespace(
    openobserve_backend: openobserveBackend,
):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE \"field name\"='value'"]
    )


def test_openobserve_value_with_wildcards(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: wildcard%value
                    fieldB: wildcard_value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE 'wildcard%value' AND fieldB LIKE 'wildcard_value'"
        ]
    )


def test_openobserve_value_contains(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: wildcard%value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE '%wildcard%value%'"
        ]
    )


def test_openobserve_value_startswith(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: wildcard%value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE 'wildcard%value%'"
        ]
    )


def test_openobserve_value_endswith(openobserve_backend: openobserveBackend):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: wildcard%value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE '%wildcard%value'"
        ]
    )


def test_openobserve_fts_keywords_str(openobserve_backend: openobserveBackend):
    with pytest.raises(Exception) as e:
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - value1
                    - value2
                condition: keywords
        """
            )
        )
    assert (
        str(e.value)
        == "Value-only string expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
    )


def test_openobserve_fts_keywords_num(openobserve_backend: openobserveBackend):
    with pytest.raises(Exception) as e:
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - 1
                    - 2
                condition: keywords
        """
            )
        )
    assert (
        str(e.value)
        == "Value-only number expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
    )


def test_openobserve_value_case_sensitive_contains(
    openobserve_backend: openobserveBackend,
):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains|cased: VaLuE
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE contains(fieldA, '*VaLuE*')"]
    )


def test_sqlite_o2_alert_output(openobserve_backend: openobserveBackend):
    rule = SigmaCollection.from_yaml(
        r"""
            id: d1736871-3a95-475a-b3ed-7d9e1d8fff99
            title: Test
            status: test
            description: test_description
            author: test_author
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value
                condition: sel
        """
    )
    assert (
        openobserve_backend.convert(rule, "o2_alert")
        == '[{"id": "d1736871-3a95-475a-b3ed-7d9e1d8fff99", "name": "Test", "org_id": "default", "stream_type": "logs", "stream_name": "{self.table}", "is_real_time": false, "query_condition": {"type": "sql", "conditions": [], "sql": "SELECT * FROM <TABLE_NAME> WHERE fieldA=\'value\'", "multi_time_range": []}, "trigger_condition": {"period": 60, "operator": ">=", "threshold": 3, "frequency": 60, "cron": "", "frequency_type": "minutes", "silence": 240, "timezone": "UTC"}, "destinations": ["<alert-destination-TBD>"], "context_attributes": {}, "row_template": "", "description": "test_description\\nlevel: \\nstatus: test\\nauthor: test_author", "enabled": true, "tz_offset": 0, "owner": "<alert-owner-TBD>"}]'
    )
