from cloudshell.cp.core.cancellation_manager import CancellationContextManager
from cloudshell.cp.core.request_actions import (
    CleanupSandboxInfraRequestActions,
    DeployedVMActions,
    DeployVMRequestActions,
    GetVMDetailsRequestActions,
    PrepareSandboxInfraRequestActions,
)
from cloudshell.shell.core.driver_context import AutoLoadDetails
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
from cloudshell.shell.core.session.logging_session import LoggingSessionContext

from cloudshell.cp.kubernetes.common.utils import dump_context
from cloudshell.cp.kubernetes.flows.autoload import AutolaodFlow
from cloudshell.cp.kubernetes.flows.cleanup import CleanupSandboxInfraFlow
from cloudshell.cp.kubernetes.flows.delete import DeleteInstanceFlow
from cloudshell.cp.kubernetes.flows.deploy import DeployFlow
from cloudshell.cp.kubernetes.flows.power import PowerFlow
from cloudshell.cp.kubernetes.flows.prepare import PrepareSandboxInfraFlow
from cloudshell.cp.kubernetes.flows.refresh_ip import RefreshIpFlow
from cloudshell.cp.kubernetes.flows.vm_details import VmDetialsFlow
from cloudshell.cp.kubernetes.models.deploy_app import KubernetesDeployApp
from cloudshell.cp.kubernetes.models.deployed_app import KubernetesDeployedApp
from cloudshell.cp.kubernetes.resource_config import KubernetesResourceConfig
from cloudshell.cp.kubernetes.services.clients import ApiClientsProvider
from cloudshell.cp.kubernetes.services.service_provider import ServiceProvider
from cloudshell.cp.kubernetes.services.tags import TagsService
from cloudshell.cp.kubernetes.services.vm_details import VmDetailsProvider


class KubernetesCloudProvider2GDriver(ResourceDriverInterface):
    SHELL_NAME = "Kubernetes Cloud Provider 2G"

    def __init__(self):
        pass

    def initialize(self, context):
        """Initialize.

        Called every time a new instance of the driver is created.

        This method can be left unimplemented but this is a good place to
        load and cache the driver configuration, initiate sessions etc.
        Whatever you choose, do not remove it.

        :param InitCommandContext context: the context the command runs on
        """
        pass

    def get_inventory(self, context):
        """Get Inventory request.

        Called when the cloud provider resource is created in the inventory.

        Method validates the values of the cloud provider attributes, entered
        by the user as part of the cloud provider resource creation.
        In addition, this would be the place to assign values programmatically to
        optional attributes that were not given a value by the user.

        If one of the validations failed, the method should raise an exception.

        :param AutoLoadCommandContext context: the context the command runs on
        :return Attribute and sub-resource information for the Shell resource you
            can return an AutoLoadDetails object
        :rtype: AutoLoadDetails
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Autoload command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = KubernetesResourceConfig.from_context(
                shell_name=self.SHELL_NAME, context=context, api=api
            )
            api_clients = ApiClientsProvider(logger).get_api_clients(resource_config)
            autoload_flow = AutolaodFlow(api_clients)
            autoload_flow.validate_config(resource_config)

        return AutoLoadDetails([], [])

    def Deploy(self, context, request, cancellation_context=None):
        """Deply request.

        Called when reserving a sandbox during setup.

        Method creates the compute resource in the cloud
        provider - VM instance or container.

        If App deployment fails, return a "success false" action result.

        :param ResourceCommandContext context:
        :param str request: A JSON string with the list of requested deployment actions
        :param CancellationContext cancellation_context:
        :return:
        :rtype: str
        """
        with LoggingSessionContext(context) as logger:
            api = CloudShellSessionContext(context).get_api()
            resource_config = KubernetesResourceConfig.from_context(
                self.SHELL_NAME, context, api
            )
            api_clients = ApiClientsProvider(logger).get_api_clients(resource_config)

            DeployVMRequestActions.register_deployment_path(KubernetesDeployApp)
            request_actions = DeployVMRequestActions.from_request(request, api)
            service_provider = ServiceProvider(
                api_clients, logger, CancellationContextManager(cancellation_context)
            )
            tag_service = TagsService(context)
            return DeployFlow(
                logger,
                resource_config,
                service_provider,
                VmDetailsProvider(),
                tag_service,
            ).deploy(request_actions)

    def PowerOn(self, context, ports):
        """Power ON request.

        Called when reserving a sandbox during setup.

        A call for each app in the sandbox can also be run manually by the
        sandbox end-user from the deployed App's commands pane.

        Method spins up the VM.

        If the operation fails, method should raise an exception.

        :param ResourceRemoteCommandContext context:
        :param ports:
        """
        with LoggingSessionContext(context) as logger:
            api = CloudShellSessionContext(context).get_api()
            resource_config = KubernetesResourceConfig.from_context(
                self.SHELL_NAME, context, api
            )
            api_clients = ApiClientsProvider(logger).get_api_clients(resource_config)
            service_provider = ServiceProvider(api_clients, logger, None)
            DeployedVMActions.register_deployment_path(KubernetesDeployedApp)
            deployed_app = DeployedVMActions.from_remote_resource(
                context.remote_endpoints[0], api
            ).deployed_app
            PowerFlow(logger, resource_config, service_provider).power_on(deployed_app)

    def remote_refresh_ip(self, context, ports, cancellation_context):
        """Refresh IP request.

        Called when reserving a sandbox during setup.

        A call for each app in the sandbox can also be run manually by the
        sandbox end-user from the deployed App's commands pane.

        Method retrieves the VM's updated IP address from the cloud provider
        and sets it on the deployed App resource.
        Both private and public IPs are retrieved, as appropriate.

        If the operation fails, method should raise an exception.

        :param ResourceRemoteCommandContext context:
        :param ports:
        :param CancellationContext cancellation_context:
        :return:
        """
        dump_context("refresh-ip-context", context, r"C:\temp\context")
        with LoggingSessionContext(context) as logger:
            api = CloudShellSessionContext(context).get_api()
            resource_config = KubernetesResourceConfig.from_context(
                self.SHELL_NAME, context, api
            )
            api_clients = ApiClientsProvider(logger).get_api_clients(resource_config)
            service_provider = ServiceProvider(api_clients, logger, None)
            DeployedVMActions.register_deployment_path(KubernetesDeployedApp)
            deployed_app = DeployedVMActions.from_remote_resource(
                context.remote_endpoints[0], api
            ).deployed_app
            RefreshIpFlow(logger, resource_config, service_provider).refresh_ip(
                deployed_app
            )

    def GetVmDetails(self, context, requests, cancellation_context):
        """Get VM details.

        Called when reserving a sandbox during setup.

        A call for each app in the sandbox can also be run manually by the sandbox
        end-user from the deployed App's VM Details pane.

        Method queries cloud provider for instance operating system, specifications
        and networking information and returns that as a json serialized driver
        response containing a list of VmDetailsData.

        If the operation fails, method should raise an exception.

        :param ResourceCommandContext context:
        :param str requests:
        :param CancellationContext cancellation_context:
        :return:
        """
        dump_context("vmditails-context", context, r"C:\temp\context")
        dump_context("vmditails-request", requests, r"C:\temp\context", obj=False)
        with LoggingSessionContext(context) as logger:
            api = CloudShellSessionContext(context).get_api()
            resource_config = KubernetesResourceConfig.from_context(
                self.SHELL_NAME, context, api
            )
            api_clients = ApiClientsProvider(logger).get_api_clients(resource_config)
            GetVMDetailsRequestActions.register_deployment_path(KubernetesDeployedApp)
            request_actions = GetVMDetailsRequestActions.from_request(requests, api)
            service_provider = ServiceProvider(
                api_clients, logger, CancellationContextManager(cancellation_context)
            )
            return VmDetialsFlow(
                logger, resource_config, service_provider, VmDetailsProvider()
            ).get_vm_details(request_actions)

    def PowerCycle(self, context, ports, delay):
        """Please leave it as is."""
        pass

    # <editor-fold desc="Power off / Delete">

    def PowerOff(self, context, ports):
        """Power Off request.

        Called during sandbox's teardown, can also be run manually
        by the sandbox end-user from the deployed App's commands pane.

        Method shuts down (or powers off) the VM instance.

        If the operation fails, method should raise an exception.

        :param ResourceRemoteCommandContext context:
        :param ports:
        """
        dump_context("poweroff-context", context, r"C:\temp\context")
        with LoggingSessionContext(context) as logger:
            api = CloudShellSessionContext(context).get_api()
            resource_config = KubernetesResourceConfig.from_context(
                self.SHELL_NAME, context, api
            )
            api_clients = ApiClientsProvider(logger).get_api_clients(resource_config)
            service_provider = ServiceProvider(api_clients, logger, None)
            DeployedVMActions.register_deployment_path(KubernetesDeployedApp)
            deployed_app = DeployedVMActions.from_remote_resource(
                context.remote_endpoints[0], api
            ).deployed_app
            PowerFlow(logger, resource_config, service_provider).power_off(deployed_app)

    def DeleteInstance(self, context, ports):
        """Delete instance.

        Called during sandbox's teardown or removing a deployed App from the sandbox.

        Method deletes the VM from the cloud provider.

        If the operation fails, method should raise an exception.

        :param ResourceRemoteCommandContext context:
        :param ports:
        """
        dump_context("delete-context", context, r"C:\temp\context")
        with LoggingSessionContext(context) as logger:
            api = CloudShellSessionContext(context).get_api()
            resource_config = KubernetesResourceConfig.from_context(
                self.SHELL_NAME, context, api
            )
            api_clients = ApiClientsProvider(logger).get_api_clients(resource_config)
            service_provider = ServiceProvider(api_clients, logger, None)
            DeployedVMActions.register_deployment_path(KubernetesDeployedApp)
            deployed_app = DeployedVMActions.from_remote_resource(
                context.remote_endpoints[0], api
            ).deployed_app
            DeleteInstanceFlow(
                logger, resource_config, service_provider
            ).delete_instance(
                deployed_app.kubernetes_name, deployed_app.name, deployed_app.namespace
            )

    def ApplyConnectivityChanges(self, context, request):
        """Apply connectivity changes request.

        Called during the orchestration setup and also called in a live sandbox when
        and instance is connected or disconnected from a VLAN
        service or from another instance (P2P connection).

        Method connects/disconnect VMs to VLANs based on requested actions
        (SetVlan, RemoveVlan).
        It's recommended to follow the "get or create" pattern when implementing
        this method.

        If operation fails, return a "success false" action result.

        :param ResourceCommandContext context: The context object for the command
        with resource and reservation info
        :param str request: A JSON string with the list of requested connectivity
        changes
        :return: a json object with the list of connectivity changes which were carried
        out by the driver
        :rtype: str
        """
        pass

    # </editor-fold>

    # <editor-fold desc="Mandatory Commands For L3 Connectivity Type">

    def PrepareSandboxInfra(self, context, request, cancellation_context):
        """Prepare Sandbox Infra.

        Called in the beginning of the orchestration flow (preparation stage),
        even before Deploy is called.

        Prepares all of the required infrastructure needed for a sandbox
        operating with L3 connectivity.
        For example, creating networking infrastructure like VPC, subnets or routing
        tables in AWS, storage entities such as S3 buckets, or keyPair objects for
        authentication.
        In general, any other entities needed on the sandbox level should be created
        here.

        Note:
        PrepareSandboxInfra can be called multiple times in a sandbox.
        Setup can be called multiple times in the sandbox, and every time setup is
        called, the PrepareSandboxInfra method will be called again.
        Implementation should support this use case and take under consideration
        that the cloud resource might already exist.
        It's recommended to follow the "get or create" pattern when implementing
        this method.

        When an error is raised or method returns action result with success false
        Cloudshell will fail sandbox creation, so bear that in mind when doing so.

        :param ResourceCommandContext context:
        :param str request:
        :param CancellationContext cancellation_context:
        :return:
        :rtype: str
        """
        with LoggingSessionContext(context) as logger:
            # parse the json strings into action objects
            api = CloudShellSessionContext(context).get_api()

            resource_config = KubernetesResourceConfig.from_context(
                self.SHELL_NAME, context, api
            )

            api_clients = ApiClientsProvider(logger).get_api_clients(resource_config)
            service_provider = ServiceProvider(
                api_clients, logger, CancellationContextManager(cancellation_context)
            )
            tag_service = TagsService(context)

            request_actions = PrepareSandboxInfraRequestActions.from_request(request)

            flow = PrepareSandboxInfraFlow(
                logger, resource_config, service_provider, tag_service
            )
            return flow.prepare(request_actions)

    def CleanupSandboxInfra(self, context, request):
        """Cleanup Sandbox infra.

        Called at the end of reservation teardown.

        Cleans all entities (beside VMs) created for sandbox,
        usually entities created in the PrepareSandboxInfra command.

        Basically all created entities for the sandbox will be deleted by
        calling the methods: DeleteInstance, CleanupSandboxInfra.

        If a failure occurs, return a "success false" action result.

        :param ResourceCommandContext context:
        :param str request:
        :return:
        :rtype: str
        """
        with LoggingSessionContext(context) as logger:
            # parse the json strings into action objects
            api = CloudShellSessionContext(context).get_api()

            resource_config = KubernetesResourceConfig.from_context(
                self.SHELL_NAME, context, api
            )

            api_clients = ApiClientsProvider(logger).get_api_clients(resource_config)
            service_provider = ServiceProvider(api_clients, logger, None)

            request_actions = CleanupSandboxInfraRequestActions.from_request(request)

            flow = CleanupSandboxInfraFlow(logger, resource_config, service_provider)
            return flow.cleanup(request_actions)

    def SetAppSecurityGroups(self, context, request):
        """Set App security groups request.

        Called via cloudshell API call.

        Programmatically set which ports will be open on each of the apps in
        the sandbox, and from where they can be accessed. This is an optional
        command that may be implemented.
        Normally, all outbound traffic from a deployed app should be allowed.
        For inbound traffic, we may use this method to specify the allowed traffic.
        An app may have several networking interfaces in the sandbox. For each such
        interface, this command allows to set which ports may be opened, the protocol
        and the source CIDR

        If operation fails, return a "success false" action result.

        :param ResourceCommandContext context:
        :param str request:
        :return:
        :rtype: str
        """
        pass

    # </editor-fold>

    def cleanup(self):
        """Cleanup request.

        Destroy the driver session, this function is called every time a
        driver instance is destroyed.
        This is a good place to close any open sessions, finish writing to log
        files, etc.
        """
        pass
