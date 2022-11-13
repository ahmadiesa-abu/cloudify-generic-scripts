## Check-Compute-Nodes usage

Background: we might need to validate compute nodes [ node_instances derived from compute ], that could have been delete outside Cloudify and deployments are left behind.

Rationale: what we will do is a simple lookup for those node instances that are in started state then checking against the info we have

**Example**:

* A deployment might have Windows/Linux Nodes -Cloudify wasn't cleaned up- and the instance was torn down, we can't just say it is deleted just yet to do that by only checking IP is not even an option [reason of that it could have been used by another Cloudify deployment or 3rd party process that took the same IP for its instance].
* So what we will do in this script we will go through all nodes and trying to actually connect and further more try to execute a set of commands to check the info -machine_name- or some other stuff as well.

```shell
chmod a+x check_computes.py
sudo -ucfyuser ./check_computes.py
```

it has argparse capability

```shell

chmod a+x check_computes.py
sudo -ucfyuser ./check_computes.py --help
usage: check_computes.py [-h] [--tenant TENANT] [--ssh-user SSH_USER]
                         [--ssh-password SSH_PASSWORD] [--ssh-key SSH_KEY]
                         [--winrm-user WINRM_USER]
                         [--winrm-password WINRM_PASSWORD] [-v]

Check Tenant Compute Nodes

optional arguments:
  -h, --help            show this help message and exit
  --tenant TENANT       Tenant to use if not passed all tenants will be
                        checked
  --ssh-user SSH_USER   SSH user to use if you want to override what Cloudify
                        has in properites
  --ssh-password SSH_PASSWORD
                        SSH password to use if you want to override what
                        Cloudify has in properites
  --ssh-key SSH_KEY     SSH private-key to use if you want to override what
                        Cloudify has in properites
  --winrm-user WINRM_USER
                        Windows user to use if you want to override what
                        Cloudify has in properites
  --winrm-password WINRM_PASSWORD
                        Windows password to use if you want to override what
                        Cloudify has in properites
  -v, --verbose         emit verbose logging

```