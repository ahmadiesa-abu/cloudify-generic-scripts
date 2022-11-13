#! /opt/manager/env/bin/python

import sys
import logging
import argparse

from sqlalchemy.orm.attributes import flag_modified
from manager_rest import config
from manager_rest.storage import get_storage_manager, models
from manager_rest.flask_utils import setup_flask_app

LOG_FORMAT = '%(asctime)s %(threadName)-20s %(levelname)-5s %(message)s'

logging.basicConfig(format=LOG_FORMAT,level=logging.INFO)
logger = logging.getLogger(__name__)

def check_owner(sm, owner):
    # this method will be used to validate the owner and return id
    if isinstance(owner, int):
        owner_rec = sm.get(models.User, owner)
        if owner_rec:
            return owner_rec.id
    else:
        # you could have passed the username so let's check that
        for user in sm.list(models.User):
            if user.username == owner:
                return user.id
    return None


def check_tenant(sm, targeted_tenant):
    # this method will be used to validate the tenant and return id
    if isinstance(targeted_tenant, int):
        tenant_rec = sm.get(models.Tenant, targeted_tenant)
        if tenant_rec:
            return tenant_rec.id
    else:
        # you could have passed the name so let's check that
        for tenant in sm.list(models.Tenant):
            if tenant.name == targeted_tenant:
                return tenant.id
    return None


def get_all_tenants(sm):
    # this method will return all the tenants ids that we have 
    tenants = []
    for tenant in sm.list(models.Tenant):
        tenants.append(tenant.id)
    return tenants


def blueprint():
    return models.Blueprint


def plugin():
    return models.Plugin


def secret():
    return models.Secret


def snapshot():
    return models.Snapshot


def deployment():
    return models.Deployment


def execution():
    return models.Execution


def dep_modification():
    return models.DeploymentModification


def dep_update_step():
    return models.DeploymentUpdateStep


def dep_update():
    return models.DeploymentUpdateStep


def event():
    return models.Event


def log():
    return models.Log


def node():
    return models.Node


def node_instance():
    return models.NodeInstance


def agent():
    return models.Agent


def task_graph():
    return models.TasksGraph


def operation():
    return models.Operation


def site():
    return models.Site


def plugins_update():
    return models.PluginsUpdate


def inter_deployment_dependency():
    return models.InterDeploymentDependencies


def deployments_label():
    return models.DeploymentLabel


def deployment_group():
    return models.DeploymentGroup


def execution_schedule():
    return models.ExecutionSchedule


def execution_group():
    return models.ExecutionGroup


def blueprints_label():
    return models.BlueprintLabel


def blueprints_filter():
    return models.BlueprintsFilter


def deployments_filter():
    return models.DeploymentsFilter


def deployment_labels_dependency():
    return models.DeploymentLabelsDependencies


def deployment_groups_label():
    return models.DeploymentGroupLabel


def log_bundle():
    return models.LogBundle

def get_class(number):
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
    try:
        return list_classes.get(number, lambda: None)()
    except:
        # return Skipped if the model is not part of cloudify version
        return 'Skipped {0} since it is not supported in this Cloudify version'.format(
                list_classes.get(number).__name__)

def change_resource_owner(sm, tenant, old_owner, new_owner, resource_type, dry_run=False):
    
    # resource type value is just an index in the list of classes
    list_class = get_class(resource_type)
    if list_class is None or (isinstance(list_class, str) and list_class.find('Skipped')>-1):
        message = 'Invalid Resource' if list_class is None else list_class
        logger.warning(message)
        return
    logger.info('Updating resource_type {0}'.format(list_class))
    for resource in sm.list(list_class, filters={
        '_tenant_id': tenant,
        '_creator_id': old_owner}):
        resource._creator_id = new_owner
        if not dry_run:
            if resource.id is not None:
                logger.debug('Update resource [{0}] to new owner'.format(resource.id))
            else:
                logger.debug('Update resource [{0}] to new owner'.format(resource._storage_id))
            flag_modified(resource, '_creator_id')
            sm.update(resource)
        else:
            if resource.id is not None:
                logger.debug('DryRun Updating resource [{0}] to new owner'.format(resource.id))  
            else:
                logger.debug('DryRun Updating resource [{0}] to new owner'.format(resource._storage_id))  


def main(dry_run, tenant, old_owner, new_owner, resource_type):
    logger.info('Inputs Provided : DryRun {0}, Tenant {1}, OldOwner {2}, '
                'NewOwner {3}'.format(dry_run, tenant, old_owner, new_owner))

    config.instance.load_from_file('/opt/manager/cloudify-rest.conf')
    config.instance.max_results = 99999999999
    with setup_flask_app().app_context():
        config.instance.load_configuration()
        sm = get_storage_manager()
        # check if user want to change ownership for one tenant
        tenant_id = None
        if tenant:
            logger.info('Validating tenant')
            tenant_id = check_tenant(sm, tenant)
            if tenant_id is None:
                logger.error('tenant {0} is not valid'.format(tenant))
                return
            else:
                logger.info('tenant is valid with id {0}'.format(tenant_id))
        old_owner_id = None
        if old_owner:
            logger.info('Validating Old Owner')
            old_owner_id = check_owner(sm, old_owner)
            if old_owner_id is None:
                logger.error('OldOwner {0} is not valid'.format(old_owner))
                return
            else:
                logger.info('OldOwner is valid with id {0}'.format(old_owner_id))
        new_owner_id = None
        if new_owner:
            logger.info('Validating New Owner')
            new_owner_id = check_owner(sm, new_owner)
            if new_owner_id is None:
                logger.error('NewOwner {0} is not valid'.format(new_owner))
                return
            else:
                logger.info('NewOwner is valid with id {0}'.format(new_owner_id))
        
        tenants = [] if not tenant else [tenant_id]
        if not tenant:
            tenants = get_all_tenants(sm)
        for tenant in tenants:    
            logger.debug('tenant_id {0}, old_owner_id {1}, new_owner_id {2}'
                        .format(tenant, old_owner_id, new_owner_id))
            if not resource_type:
                # go over the list of resources
                for i in range(1,30):
                    change_resource_owner(sm, tenant, old_owner_id, new_owner_id, i, dry_run)
            else:
                change_resource_owner(sm, tenant, old_owner_id, new_owner_id, resource_type, dry_run)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Change Tenant Resources Owner')
    parser.add_argument('-d', '--dry-run',
                    help='If set, will not save changes',
                    action='store_true')
    parser.add_argument(
        '--tenant',
        metavar='TENANT',
        default=None,
        help="Tenant to use if not passed all tenants will be affected"
    )
    parser.add_argument(
        '--old-owner',
        metavar='OLD_OWNER',
        default=None,
        help="Old Owner of the resources you wish to change owner for"
    )
    parser.add_argument(
        '--new-owner',
        metavar='NEW_OWNER',
        default=None,
        help="New Owner of the resources you wish to change owner for"
    )
    parser.add_argument(
        '--resource-type',
        metavar='RESOURCE_TYPE',
        default=None,
        help="resource_type you wish to change owner for [1-29]"
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
    
    main(args.dry_run, args.tenant, args.old_owner, args.new_owner, args.resource_type)
