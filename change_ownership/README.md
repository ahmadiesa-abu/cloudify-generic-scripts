## Change-Ownership usage

Background: we have limited implementation in the cli to change resources ownership [ this script to address missing implementations ]

```shell
chmod a+x change_ownership.py
sudo -ucfyuser ./change_ownership.py
```

it has argparse capability

```shell

sudo -ucfyuser ./change_ownership.py --help
usage: change_ownership.py [-h] [-d] [--tenant TENANT] [--old-owner OLD_OWNER]
                           [--new-owner NEW_OWNER]
                           [--resource-type RESOURCE_TYPE] [-v]

Change Tenant Resources Owner

optional arguments:
  -h, --help            show this help message and exit
  -d, --dry-run         If set, will not save changes
  --tenant TENANT       Tenant to use if not passed all tenants will be
                        affected
  --old-owner OLD_OWNER
                        Old Owner of the resources you wish to change owner
                        for
  --new-owner NEW_OWNER
                        New Owner of the resources you wish to change owner
                        for
  --resource-type RESOURCE_TYPE
                        resource_type you wish to change owner for [1-29]
  -v, --verbose         emit verbose logging

```

Resource Type mapping 

```python
list_classes = {
    1: blueprint,
    2: plugin,
    3: secret,
    4: snapshot,
    5: deployment,
    6: execution,
    7: dep_modification,
    8: dep_update_step,
    9: dep_update,
    10: event,
    11: log,
    12: node,
    13: node_instance,
    14: agent,
    15: task_graph,
    16: operation,
    17: site,
    18: plugins_update,
    19: inter_deployment_dependency,
    20: deployments_label,
    21: deployment_group,
    22: execution_group,
    23: execution_schedule,
    24: blueprints_label,
    25: blueprints_filter,
    26: deployments_filter,
    27: deployment_labels_dependency,
    28: deployment_groups_label,
    29: log_bundle,
    30: lambda: None
}
```