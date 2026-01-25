"""pySigma pipeline for kunai on openobserve"""

# pylint: disable=missing-function-docstring

from sigma.pipelines.common import (
    logsource_linux_process_creation,
    logsource_linux_file_create,
    logsource_linux_network_connection,
)
from sigma.processing.transformations import (
    ReplaceStringTransformation,
    AddConditionTransformation,
    # ChangeLogsourceTransformation,
    DropDetectionItemTransformation,
    FieldMappingTransformation,
    DetectionItemFailureTransformation,
    # MapStringTransformation,
)
from sigma.processing.conditions import (
    # RuleContainsDetectionItemCondition,
    IncludeFieldCondition,
    MatchStringCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.finalization import ConcatenateQueriesFinalizer

cond_field_parentbasefilename = IncludeFieldCondition(fields=["ParentBaseFileName"])
cond_field_contextbasefilename = IncludeFieldCondition(fields=["ContextBaseFileName"])


def generate_unsupported_process_field_processing_item(field):
    return ProcessingItem(
        identifier=f"kunai_fail_process_start_{field}",
        transformation=DetectionItemFailureTransformation(
            f"Kunai does not support the {field} field"
        ),
        rule_conditions=[logsource_linux_process_creation()],
        field_name_conditions=[IncludeFieldCondition(fields=[field])],
    )


def common_processing_items():
    return [
        ProcessingItem(
            identifier="kunai_process_creation_nix",
            transformation=AddConditionTransformation(
                {"os_type": "linux", "info_event_name": ["execve", "execve_script"]}
            ),
            rule_conditions=[
                logsource_linux_process_creation(),
            ],
        ),
        # https://why.kunai.rocks/docs/events/execve
        ProcessingItem(
            identifier="kunai_process_creation_fieldmaping",
            transformation=FieldMappingTransformation(
                {
                    "Image": "data_exe_path",
                    "CommandLine": "data_command_line",
                    "ParentImage": "data_ancestors",
                    "ParentCommandLine": "parent_command_line",
                    "User": "info_task_user",
                    "ProcessId": "info_task_pid",
                    "ParentProcessId": "info_parent_task_pid",
                    "Computer": "host_name",
                    "md5": "data_exe_md5",
                    "sha1": "data_exe_sha1",
                    "sha256": "data_exe_sha256",
                    # "?": "data_exe_sha512",
                }
            ),
            rule_conditions=[
                logsource_linux_process_creation(),
            ],
            rule_condition_linking=any,
        ),
        ProcessingItem(
            identifier="kunai_process_creation_drop_currentdirectory",
            transformation=DropDetectionItemTransformation(),
            rule_conditions=[
                logsource_linux_process_creation(),
            ],
            field_name_conditions=[
                IncludeFieldCondition(fields=["CurrentDirectory"]),
            ],
        ),
        # Handle unsupported process start events
        generate_unsupported_process_field_processing_item("CurrentDirectory"),
        generate_unsupported_process_field_processing_item("imphash"),
        generate_unsupported_process_field_processing_item("FileVersion"),
        generate_unsupported_process_field_processing_item("Description"),
        generate_unsupported_process_field_processing_item("Product"),
        generate_unsupported_process_field_processing_item("Company"),
        generate_unsupported_process_field_processing_item("LogonGuid"),
        generate_unsupported_process_field_processing_item("ParentProcessGuid"),
        # ParentBaseFileName handling
        ProcessingItem(
            identifier="kunai_parentbasefilename_fail_completepath",
            transformation=DetectionItemFailureTransformation(
                "Kunai provides parent image tree in data_ancestors field."
            ),
            field_name_conditions=[
                cond_field_parentbasefilename,
            ],
            detection_item_conditions=[
                MatchStringCondition(
                    cond="any",
                    pattern="^\\*\\\\?[^\\\\]+$",
                    negate=True,
                ),
            ],
        ),
        ProcessingItem(
            identifier="kunai_parentbasefilename_executable_only",
            transformation=ReplaceStringTransformation(
                regex="^\\*\\\\([^\\\\]+)$",
                replacement="\\1",
            ),
            field_name_conditions=[
                cond_field_parentbasefilename,
            ],
        ),
        # https://why.kunai.rocks/docs/events/file_create
        ProcessingItem(
            identifier="kunai_file_nix",
            transformation=AddConditionTransformation(
                {"os_type": "linux", "info_event_name": ["file_create", "file_unlink"]}
            ),
            rule_conditions=[
                logsource_linux_file_create(),
            ],
        ),
        ProcessingItem(
            identifier="kunai_file_create_fieldmaping",
            transformation=FieldMappingTransformation(
                {
                    "Image": "data_exe_path",
                    "ParentImage": "data_ancestors",
                    "User": "info_task_user",
                    "ProcessId": "info_task_pid",
                    "ParentProcessId": "info_parent_task_pid",
                    "Computer": "host_name",
                    "TargetFilename": "data_path",
                }
            ),
            rule_conditions=[
                logsource_linux_file_create(),
            ],
            rule_condition_linking=any,
        ),
        # https://why.kunai.rocks/docs/events/connect
        ProcessingItem(
            identifier="kunai_network_fieldmaping",
            transformation=FieldMappingTransformation(
                {
                    "Image": "data_exe_path",
                    "ParentImage": "data_ancestors",
                    "User": "info_task_user",
                    "ProcessId": "info_task_pid",
                    "ParentProcessId": "info_parent_task_pid",
                    "Computer": "host_name",
                    "DestinationHostname": "data_dst_hostname",
                    "DestinationIp": "data_dst_ip",
                    # "?": "data_dst_is_v6",
                    "DestinationPort": "data_dst_port",
                    # "?": "data_dst_public",
                    # "?": "data_socket_domain",
                    # "?": "data_socket_proto",
                    # "?": "data_socket_type",
                    # "?": "data_src_ip",
                    # "?": "data_src_port",
                }
            ),
            rule_conditions=[
                logsource_linux_network_connection(),
            ],
            rule_condition_linking=any,
        ),
        ProcessingItem(
            identifier="kunai_network_connection_drop_initiated",
            transformation=DropDetectionItemTransformation(),
            rule_conditions=[
                logsource_linux_network_connection(),
            ],
            field_name_conditions=[
                IncludeFieldCondition(fields=["Initiated"]),
            ],
        ),
    ]


def kunai_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Kunai Pipeline",
        priority=10,
        items=[
            # Process Creation
            ProcessingItem(
                identifier="kunai_process_creation_eventtype",
                transformation=AddConditionTransformation(
                    {"info_event_name": ["execve", "execve_script"]}
                ),
                rule_conditions=[
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            # File
            ProcessingItem(
                identifier="kunai_process_create_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "os_type": "linux",
                        "info_event_name": ["file_create", "file_unlink"],
                    }
                ),
                rule_conditions=[
                    logsource_linux_file_create(),
                ],
                rule_condition_linking=any,
            ),
            # Network
            ProcessingItem(
                identifier="kunai_network_connection_eventtype",
                transformation=AddConditionTransformation(
                    {"info_event_name": ["connect"]}
                ),
                rule_conditions=[
                    logsource_linux_network_connection(),
                ],
                rule_condition_linking=any,
            ),
        ]
        + common_processing_items(),
        finalizers=[ConcatenateQueriesFinalizer()],
    )
