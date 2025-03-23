![Tests](https://github.com/juju4/pySigma-backend-openobserve/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/juju4/TODO/raw/test.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma OpenObserve Backend

This is the OpenObserve backend for pySigma. It provides the package `sigma.backends.openobserve` with the `openobserveBackend` class.

It supports the following output formats:

* **default**: plain SQL for [OpenObserve](https://openobserve.ai/docs/sql_reference/) / [Apache Datafusion](https://datafusion.apache.org/user-guide/sql/index.html)
* **alerts**: [OpenObserve Alerts json](https://YOURSERVER/swagger/#/Alerts/CreateAlert) - TODO/FIXME!

This backend is currently maintained by:

* [juju4](https://github.com/juju4/)

## Known issues/limitations

* Be aware that OpenObserve
  * has currently (2025) no field name normalization and as such, tables, field names, and pipelines are environment dependent. Included pipeline are based on ingestion with opentelemetry-collector-contrib (default, journald, zeek, kunai).
  * flatten json by default.
* Full Text Search to implement (match_all).
* Support cidr filter.
* Validate SQL with `sqlglot.transpile(sql)`

# Quick Start

## Example script (default output) with sysmon pipeline

### Add pipelines

```shell
poetry add pysigma-pipeline-sysmon
poetry add pysigma-pipeline-windows
```

### Convert a rule

```python
from sigma.collection import SigmaCollection
from sigma.backends.openobserve import openobserve
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline

from sigma.processing.resolver import ProcessingPipelineResolver

# Create the pipeline resolver
piperesolver = ProcessingPipelineResolver()
# Add pipelines
piperesolver.add_pipeline_class(sysmon_pipeline()) # Syssmon
piperesolver.add_pipeline_class(windows_logsource_pipeline()) # Windows
# Create a combined pipeline
combined_pipeline = piperesolver.resolve(piperesolver.pipelines)
# Instantiate backend using the combined pipeline
openobserve_backend = openobserve.openobserveBackend(combined_pipeline)

rule = SigmaCollection.from_yaml(
r"""
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
""")

print(openobserve_backend.convert(rule)[0])

```

## Running

```shell
poetry run python3 example.py
```

# Thanks

* SigmaHQ and its contributors.
* wagga for the sqlite backend from which this one is adapted.
