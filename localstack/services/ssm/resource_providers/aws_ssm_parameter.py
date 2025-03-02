from __future__ import annotations

import uuid
from typing import Optional, Type, TypedDict

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class SSMParameterProperties(TypedDict):
    Type: str
    Value: str
    AllowedPattern: Optional[str]
    DataType: Optional[str]
    Description: Optional[str]
    Id: Optional[str]
    Name: Optional[str]
    Policies: Optional[str]
    Tags: Optional[dict]
    Tier: Optional[str]


INITIALISED_KEY = "initialised"


def short_uid() -> str:
    return str(uuid.uuid4())[0:8]


class SSMParameterProvider(ResourceProvider[SSMParameterProperties]):
    TYPE = "AWS::SSM::Parameter"

    def create(
        self,
        request: ResourceRequest[SSMParameterProperties],
    ) -> ProgressEvent[SSMParameterProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id

        Required properties:
          - Type
          - Value

        Create-only properties:
          - /properties/Name

        Read-only properties:
          - /properties/Id

        """
        model = request.desired_state

        # validation
        assert model.get("Type") in {"String", "SecureString", "StringList"}
        assert model.get("Value") is not None

        if not request.custom_context.get(INITIALISED_KEY):
            # this is the first time this callback is invoked

            # defaults
            if model.get("DataType") is None:
                model["DataType"] = "text"

            if model.get("Name") is None:
                # TODO: fix auto-generation
                model["Name"] = f"param-{short_uid()}"

            # idempotency
            try:
                request.aws_client_factory.ssm.get_parameter(Name=model["Name"])
            except request.aws_client_factory.ssm.exceptions.ParameterNotFound:
                pass
            else:
                # the resource already exists
                # for now raise an exception
                # TODO: return progress event
                raise RuntimeError(f"ssm parameter: {model['Name']} already exists")

            # create the resource
            res = request.aws_client_factory.ssm.put_parameter(
                Name=model["Name"],
                Type=model["Type"],
                Value=model["Value"],
            )
            model["Tier"] = res.get("Tier", "Standard")

            request.custom_context[INITIALISED_KEY] = True
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        res = request.aws_client_factory.ssm.get_parameter(Name=model["Name"])["Parameter"]
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=res)

    def read(
        self,
        request: ResourceRequest[SSMParameterProperties],
    ) -> ProgressEvent[SSMParameterProperties]:
        """
        Fetch resource information
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[SSMParameterProperties],
    ) -> ProgressEvent[SSMParameterProperties]:
        """
        Delete a resource
        """
        name = request.desired_state["Name"]
        request.aws_client_factory.ssm.delete_parameter(Name=name)
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=request.desired_state)

    def update(
        self,
        request: ResourceRequest[SSMParameterProperties],
    ) -> ProgressEvent[SSMParameterProperties]:
        """
        Update a resource
        """
        raise NotImplementedError


class SSMParameterProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SSM::Parameter"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        self.factory = SSMParameterProvider
