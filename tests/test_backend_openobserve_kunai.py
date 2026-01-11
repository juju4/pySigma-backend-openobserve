"""OpenObserve backend for pySigma Tests"""

# pylint: disable=line-too-long,fixme,invalid-name,missing-function-docstring,redefined-outer-name
import json
import pytest
from sigma.collection import SigmaCollection
from sigma.backends.openobserve import openobserveBackend


@pytest.fixture
def openobserve_backend():
    return openobserveBackend()


def test_openobserve_sigma_rule_lnx_doas_execution1(
    openobserve_backend: openobserveBackend,
):
    assert (
        openobserve_backend.convert(
            SigmaCollection.from_yaml(
                """
title: Linux Doas Tool Execution
id: 067d8238-7127-451c-a9ec-fa78045b618b
status: stable
description: Detects the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does.
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/doas'
    condition: selection
level: low
                """
            )
        )
        == [
            """SELECT data_command_line,data_exe_path,info_event_name,info_parent_task_name,info_task_name,info_task_uid FROM <TABLE_NAME> WHERE (os_type='linux' AND (info_event_name='execve' OR info_event_name LIKE 'execve_script')) AND ((info_event_name='execve' OR info_event_name LIKE 'execve_script') AND data_exe_path LIKE '%/doas')"""
        ]
    )


def test_openobserve_sigma_rule_lnx_doas_execution2(
    openobserve_backend: openobserveBackend,
):
    rule_out = openobserve_backend.convert(
        SigmaCollection.from_yaml(
            """
title: Linux Doas Tool Execution
id: 067d8238-7127-451c-a9ec-fa78045b618b
status: stable
description: Detects the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does.
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/doas'
    condition: selection
level: low
                """
        ),
        "o2alert",
    )

    rule_json = json.loads(rule_out)
    assert rule_json[0]["name"] == "Linux_Doas_Tool_Execution"
    assert (
        rule_json[0]["query_condition"]["sql"]
        == """SELECT data_command_line,data_exe_path,info_event_name,info_parent_task_name,info_task_name,info_task_uid FROM "<TABLE_NAME>" WHERE (os_type=\'linux\' AND (info_event_name=\'execve\' OR info_event_name LIKE \'execve_script\')) AND ((info_event_name=\'execve\' OR info_event_name LIKE \'execve_script\') AND data_exe_path LIKE \'%/doas\')"""
    )
