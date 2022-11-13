#! /opt/manager/env/bin/python

import os
import sys
import copy
import json
import queue as Queue
import logging
import argparse
import threading

from io import StringIO
from datetime import datetime
from distutils.version import StrictVersion

from manager_rest import config
from manager_rest.dsl_functions import evaluate_node
from manager_rest.storage import get_storage_manager, models
from cloudify.models_states import DeploymentState, AgentState
from manager_rest.flask_utils import setup_flask_app

LOG_FORMAT = '%(asctime)s %(threadName)-20s %(levelname)-5s %(message)s'

logging.basicConfig(format=LOG_FORMAT,level=logging.INFO)
logger = logging.getLogger(__name__)

# defining a global checking queue
checking_queue = Queue.Queue()

# global dict to store results and failures
status_counters = {
    'valid_instances_count': 0,
    'invalid_instances_count': 0,
    'invalid_instances_details': [],
    'candidate_tenant_node_instances': []
}

# global threading lock to control the results dumping to result file
report_lock = threading.Lock()

# result file will be created each run to store what we gatherd for audit later
THIS_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
now = datetime.now()
file_name = 'check_compute_nodes_{check_time}.log'.format(check_time=now.strftime("%Y%m%d%H%M%S"))
check_path = os.path.join(THIS_DIRECTORY, file_name)

# PRIVATE_KEY handling CONSTANT
PRIVATE_KEY_PREFIX = '-----BEGIN'


# a small trick to include pywinrm and fabric from mgmtworker venv
def get_site_packages():
    def _get_formatted_version(version):
        try:
            version = version.replace('python', '')
            return StrictVersion(version)
        except ValueError:
            return None

    path_base = '/opt/mgmtworker/env/lib'
    package_dirs = next(os.walk(path_base))[1]
    versions = package_dirs
    newest = max(versions, key=_get_formatted_version)
    path_base += '/{0}/site-packages'.format(newest)
    return path_base


site_packages = get_site_packages()
sys.path.append(site_packages)
try:
    from winrm import Session
    from fabric import Connection
    from paramiko import RSAKey, ECDSAKey, Ed25519Key, SSHException
    logger.info('Loaded pywinrm and fabric libraries')
except ImportError as e:
    Session = None
    Connection = None
    RSAKey = ECDSAKey = Ed25519Key = SSHException = None
    logger.error('OOps , can not import either '
        'fabric or pywinrm and possibly both')
    pass


def check_tenant(sm, targeted_tenant):
    # this method will be used to validate the tenant and return id
    if isinstance(targeted_tenant, int):
        tenant_rec = sm.get(models.Tenant, targeted_tenant)
        if tenant_rec:
            return {'id': tenant_rec.id, 'name': tenant_rec.name}
    else:
        # you could have passed the name so let's check that
        for tenant in sm.list(models.Tenant):
            if tenant.name == targeted_tenant:
                return {'id': tenant.id, 'name': tenant.name}
    return None


def get_all_tenants(sm):
    # this method will return all the tenants ids that we have 
    tenants = []
    for tenant in sm.list(models.Tenant):
        tenants.append({'id': tenant.id, 'name': tenant.name})
    return tenants


def check_windows_node(instance_connection_details):
    # this method should check connectivty to the instance, then get more data from it
    # by connecting to the widnows instance and execute commands then 
    # check against the value we prepared while reading properties from Cloudify

    try:
        # try to connect to the windows machine and execute some commands
        win_ip = instance_connection_details.get('host_ip')
        winrm_user = instance_connection_details.get('host_user')
        winrm_password = instance_connection_details.get('host_pass')
        values_to_check = instance_connection_details.get('values_to_check', {})
        session = Session(auth=(winrm_user, winrm_password), transport=u'ntlm', target=win_ip)

        # check things we set out to validate
        for key, value in values_to_check.items():
            command = ''
            is_ps = False
            if key == 'hostname':
                command = 'hostname'
            elif key == 'creation_time':
                command = '(Get-WmiObject Win32_OperatingSystem).InstallDate'
                is_ps = True
            else:
                logger.debug('this value check-command is not implemeted')
            if command:
                response = session.run_cmd(command) if not is_ps else session.run_ps(command)

                error_code = response.status_code if hasattr(response, 'status_code') \
                    and response.status_code is not None else -1
                response_out = response.std_out.decode('utf-8').rstrip() if hasattr(response, 'std_out') \
                        and response.std_out is not None else 'N/A'
                response_err = response.std_err.decode('utf-8').rstrip() if hasattr(response, 'std_err') \
                        and response.std_err is not None else 'N/A'
                
                # success let's compare with what we expect
                if error_code == 0:
                    response_out = response_out if key != 'creation_time' else response_out[:8]
                    if response_out != value:
                        logger.debug('command {0} causing discrepancy [output] {1} and [value] {2}'.format(
                            command, response_out, value))
                        return False
                else:
                    logger.debug('command {0} failed with [output] {1} and [error] {2}'.format(
                        command, response_out, response_err))
                    return False
    except Exception as e:
        logger.debug('Connection/Generic Exception from check_windows_node {0}'.format(str(e)))
        logger.error('Could not connect to [{0}] to check the node'.format(win_ip))
        return False
    # if we reach here it means we have everything as we expect and it is a valid instance
    return True


def check_linux_node(instance_connection_details):
    # this method should check connectivty to the instance, then get more data from it
    # by connecting to the linux instance and execute commands then 
    # check against the value we prepared while reading properties from Cloudify

    def _load_private_key(key_contents):
        for cls in (RSAKey, ECDSAKey, Ed25519Key):
            try:
                return cls.from_private_key(StringIO(key_contents))
            except SSHException:
                continue
        return 'N/A'

    try:
        # try to connect to the linux machine and execute some commands
        linux_ip = instance_connection_details.get('host_ip')
        linux_user = instance_connection_details.get('host_user')
        linux_password = instance_connection_details.get('host_pass')
        linux_key = instance_connection_details.get('host_key')
        values_to_check = instance_connection_details.get('values_to_check', {})

        # Prepare Connection data dict 
        attributes = {
            'hide': True,
            'warn': True,
        }
        env = {
            'forward_agent': True,
            'host': linux_ip,
            'port': 22,
            'user': linux_user,
            'connect_kwargs': {},
        }
        if linux_key and isinstance(linux_key, str):
            if linux_key.startswith(PRIVATE_KEY_PREFIX):
                env['connect_kwargs']['pkey'] = _load_private_key(linux_key)
            else:
                env['connect_kwargs']['key_filename'] = os.path.expanduser(linux_key)

        if linux_password:
            env['connect_kwargs']['password'] = linux_password

        connection = Connection(**env)
        connection.open()

        # check things we set out to validate
        for key, value in values_to_check.items():
            command = ''
            if key == 'hostname':
                command = 'hostname'
            else:
                logger.debug('this value check-command is not implemeted')
            if command:
                response = connection.run(command, **attributes)
                error_code = response.return_code if hasattr(response, 'return_code') \
                    and response.return_code is not None else -1
                response_out = response.stdout.rstrip() if hasattr(response, 'stdout') \
                        and response.stdout is not None else 'N/A'
                response_err = response.stderr.rstrip() if hasattr(response, 'stderr') \
                        and response.stderr is not None else 'N/A'

                # success let's compare with what we expect
                if error_code == 0:
                    if response_out != value:
                        logger.debug('command {0} causing discrepancy [output] {1} and [value] {2}'.format(
                            command, response_out, value))
                        return False
                else:
                    logger.debug('command {0} failed with [output] {1} and [error] {2}'.format(
                        command, response_out, response_err))
                    return False
    except Exception as e:
        logger.debug('Connection/Generic Exception from check_linux_node {0}'.format(str(e)))
        logger.error('Could not connect to [{0}] to check the node'.format(linux_ip))
        return False
    # if we reach here it means we have everything as we expect and it is a valid instance
    return True


def check_node(checking_queue):
    
    # use global variables with locking updating 
    global check_path
    global report_lock
    global status_counters

    while True:
        try:
            node_instance = checking_queue.get(block=False)
        except Queue.Empty:
            break
        logger.info('Checking validity of Node {{{0}}} from deployment {{{1}}}'.format(
            node_instance.get('node_instance_id'), node_instance.get('deployment_id')))
        
        invalid = failed = False
        connection_details = node_instance.get('connection_details', {})
        if node_instance.get('connection_type', '') == 'Linux':
            if Connection is not None:
                failed = not check_linux_node(connection_details)
            else:
                logger.debug('Skipping {{{0}}} check as fabric library not loaded'.format(
                    node_instance.get('node_instance_id')))
        elif node_instance.get('connection_type', '') == 'Windows':
            if Session is not None:
                failed = not check_windows_node(connection_details)
            else:
                logger.debug('Skipping {{{0}}} check as pywinrm library not loaded'.format(
                    node_instance.get('node_instance_id')))
        else:
            invalid = True

        with report_lock:
            if invalid or failed:
                status_counters['invalid_instances_count'] += 1
                status_counters['invalid_instances_details'].append(node_instance)
            elif not invalid:
                status_counters['valid_instances_count'] += 1

            with open(check_path, 'w') as f:
                json.dump(status_counters, f, indent=4)



def check_tenant_compute_nodes(sm, tenant, ssh_user, ssh_password, ssh_key,
                               winrm_user, winrm_password):
    global status_counters
    # a list that will hold the node_instances 
    # -items would be dicts of infomation we think is relevant-
    # that we will be checking with connecting and validating the properties against
    candidate_tenant_node_instances = []

    def print_table(data, cols, wide):
        # this method just to show final number in a better way
        final_result = ""
        n, r = divmod(len(data), cols)
        pat = '{{:{}}}'.format(wide)
        line = '\n'.join(pat * cols for _ in range(n))
        last_line = pat * r
        final_result += "{0}\n".format(line.format(*data))
        final_result += "{0}\n".format(last_line.format(*data[n*cols:]))
        return final_result

    logger.info('Checking node instances for tenant {{{0}}}'.format(tenant.get('name')))

    for deployment in sm.list(models.Deployment, filters={
            '_tenant_id': tenant.get('id'),
            'installation_status': DeploymentState.ACTIVE}):
        
        logger.debug('Checking Deployment {{{0}}} Nodes'.format(deployment.id))

        # since we have active deployment let's check its nodes
        for node in sm.list(models.Node, filters={
                '_tenant_id': tenant.get('id'),
                '_deployment_fk': deployment._storage_id,
                }):
            logger.debug('Checking Node {0} in Deployment {1} Candidacy'.format(
                node.id, deployment.id))
            
            logger.debug('Node {{{0}}} {1}'.format(node.id, 'is not applicable'
                if node.host_id is None else 'is a candidate'))

            # weed out non host -we are only interested in possible Compute Nodes-
            if node.host_id is None:
                continue

            logger.debug('Going to check Node {{{0}}} in Deployment {{{1}}} '
                'from Tenant {{{2}}}'.format(node.id, deployment.id, tenant.get('name')))

            # check the type hierarchy straight forward in rare cases if we have messed up hierarchy 
            # we will check properties if agent_config is there that means at some point in time 
            # the type was compute for sure [ at least that is the assumption we could add more specialized
            # checking maybe the whole dict structure ]

            if 'cloudify.nodes.Compute' in node.type_hierarchy \
                    or ('cloudify.nodes.Root' in node.type_hierarchy
                        and 'agent_config' in node.properties):
                logger.debug('Node {{{0}}} with type {{{1}}} '
                    'is exactly the node we want to check'.format(node.id, node.type))

                logger.debug('Checking Deployment {{{0}}} NodeInstances from type {{{1}}}'.format(
                    deployment.id, node.type))

                # Getting the node_instances from that node inside the deployment
                # right now we are checking started state we might change it to include other cases
                # some point in install workflow configure or even create does everything for you 
                # create the vm , .... 

                for node_instance in sm.list(models.NodeInstance, filters={
                        '_tenant_id': tenant.get('id'),
                        '_node_fk': node._storage_id,
                        'state': AgentState.STARTED,
                        }):
                    logger.debug('Going to check NodeInstance {{{0}}} in Deployment {{{1}}} '
                        'from Tenant {{{2}}}'.format(node_instance.id, deployment.id, tenant.get('name')))

                    # prepare connection details from properties & runtime properties
                    _node = {
                        'id': node.id,
                        'deployment_id': deployment.id,
                        'properties': node.to_dict().get('properties', {}),
                    }
                    evaluated_node = evaluate_node(_node)
                    properties = evaluated_node.get('properties', {})
                    runtime_props = node_instance.runtime_properties

                    # getting the ip from runtime first of course 
                    host_ip = runtime_props.get('public_ip', runtime_props.get('ip', properties.get('ip','N/A')))
                    
                    # host os family is defined in the Compute Node properties with linux as default 
                    # we overrride it in our plugins i.e. azure let's use it , and if it gives us N/A we will use 
                    # the port to determine linux/windows though that is not accurate but let's work with 
                    # what we have for now 
                    host_os_family = properties.get('os_family', 'N/A')
                    
                    # relying on agent_config properties for other stuff for now
                    # and we will have also the passed paramters that the user will use
                    # to check for connectivity
                    host_user = properties.get('agent_config', {}).get('user', 'N/A')
                    host_pass = properties.get('agent_config', {}).get('password', 'N/A')
                    host_key = properties.get('agent_config', {}).get('key', 'N/A')
                    host_port = properties.get('agent_config', {}).get('port', 'N/A')

                    # figuring out the values that we want to get
                    creation_time = deployment.created_at[:10].replace('-', '')
                    # check Azure convention vs AWS
                    host_name = runtime_props.get('name', runtime_props.get('resource', {}).get(
                        'PrivateDnsName', 'N/A'))

                    conn_type = 'Windows' if host_os_family == 'windows' or host_port==5985 \
                                          else 'Linux'


                    # let's override based on the user provided
                    if ssh_user:
                        host_user = ssh_user if conn_type == 'Linux' else winrm_user
                    if ssh_password:
                        host_pass = ssh_password if conn_type == 'Linux' else winrm_password
                    if ssh_key:
                        host_key = ssh_key


                    candidate_tenant_node_instances.append({
                        'deployment_id': deployment.id,
                        'node_instance_id': node_instance.id,
                        'connection_type': conn_type,
                        'connection_details': {
                            'host_ip': host_ip,
                            'host_user': host_user,
                            'host_pass': host_pass,
                            'host_key': host_key,
                            'values_to_check': {
                                'hostname': host_name,
                                'creation_time': creation_time,
                            }
                        },
                    })

    logger.debug('Node instances to check for tenant {{{0}}} : {{{1}}}'.format(
            tenant.get('name'), candidate_tenant_node_instances))

    # store the raw data inside the global status dict
    status_counters['candidate_tenant_node_instances'] = candidate_tenant_node_instances
    
    logger.debug('Putting the dicts into a queue so we can distribute load')
    for node_instance in candidate_tenant_node_instances:
        checking_queue.put(node_instance)
    
    # let's use some threading to handle the list which is way faster
    threads = list()
    for i in range(20):
        t = threading.Thread(target=check_node, args=(checking_queue,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # let's log stats only the full data is part of the file already
    data = [
        '{0}{1}'.format(' '*5,'Type'), '{0}{1}'.format(' '*16,'Number'),
        '{0}{1}'.format(' '*5,'___'), '{0}{1}'.format(' '*16,'______'),
        '{0}{1}'.format(' '*5,'   '), '{0}{1}'.format(' '*16,'      '),
        'Valid hosts count', status_counters.get('valid_instances_count', 0),
        '                ', '    ',
        'Invalid hosts count', status_counters.get('invalid_instances_count', 0),
    ]
    contents = print_table(data, 2, 20)
    line_length = len(contents.splitlines()[0])
    final_stats = "\nFinal Numbers are : \n{0}\n{1}\n{0}\n{2}".format(
            "_" * line_length, contents, "Check file {0} for full details".format(check_path))
    logger.info(final_stats)
    


def main(tenant, ssh_user, ssh_password, ssh_key, winrm_user, winrm_password):
    logger.info('Inputs Provided : Tenant {0}, SSH User {1}, SSH Password {2}, '
        'SSH Key {3}, WINRM User {4}, WINRM Passord {5}'.format(tenant,
            ssh_user, ssh_password, ssh_key, winrm_user, winrm_password))

    config.instance.load_from_file('/opt/manager/cloudify-rest.conf')
    config.instance.max_results = 99999999999
    with setup_flask_app().app_context():
        config.instance.load_configuration()
        sm = get_storage_manager()
        # check if a valid tenant is passed
        tenant_id = None
        if tenant:
            logger.info('Validating tenant')
            tenant_id = check_tenant(sm, tenant)
            if tenant_id is None:
                logger.error('tenant {0} is not valid'.format(tenant))
                return
            else:
                logger.info('tenant is valid with id {0}'.format(tenant_id.get('id')))
        
        tenants = [] if not tenant else [tenant_id]
        if not tenant:
            tenants = get_all_tenants(sm)
        for tenant in tenants:    
            logger.debug('tenant_id {0}'.format(tenant.get('id')))
            check_tenant_compute_nodes(sm, tenant, ssh_user, ssh_password, ssh_key,
                                       winrm_user, winrm_password)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Check Tenant Compute Nodes')
    parser.add_argument(
        '--tenant',
        metavar='TENANT',
        default=None,
        help="Tenant to use if not passed all tenants will be checked"
    )
    parser.add_argument(
        '--ssh-user',
        metavar='SSH_USER',
        default=None,
        help="SSH user to use "
              "if you want to override what Cloudify has in properites"
    )
    parser.add_argument(
        '--ssh-password',
        metavar='SSH_PASSWORD',
        default=None,
        help="SSH password to use "
              "if you want to override what Cloudify has in properites"
    )
    parser.add_argument(
        '--ssh-key',
        metavar='SSH_KEY',
        default=None,
        help="SSH private-key to use "
             "if you want to override what Cloudify has in properites"
    )
    parser.add_argument(
        '--winrm-user',
        metavar='WINRM_USER',
        default=None,
        help="Windows user to use "
             "if you want to override what Cloudify has in properites"
    )
    parser.add_argument(
        '--winrm-password',
        metavar='WINRM_PASSWORD',
        default=None,
        help="Windows password to use "
             "if you want to override what Cloudify has in properites"
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        default=False,
        help="emit verbose logging")
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    main(args.tenant, args.ssh_user, args.ssh_password, args.ssh_key,
         args.winrm_user, args.winrm_password)

