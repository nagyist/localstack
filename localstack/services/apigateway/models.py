import base64
import json
from collections import defaultdict
from enum import Enum
from http.cookiejar import Cookie
from typing import Any, Dict, List, Optional, Union

from requests.structures import CaseInsensitiveDict

from localstack.aws.api.apigateway import (
    Authorizer,
    DocumentationPart,
    GatewayResponse,
    Model,
    RequestValidator,
    RestApi,
)
from localstack.constants import HEADER_LOCALSTACK_EDGE_URL
from localstack.http import Response
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.aws import arns
from localstack.utils.aws.aws_responses import parse_query_string
from localstack.utils.objects import snake_to_camel
from localstack.utils.strings import short_uid, to_str

# type definition for data parameters (i.e., invocation payloads)
InvocationPayload = Union[Dict, str, bytes]


class RestApiContainer:
    # contains the RestApi dictionary. We're not making use of it yet, still using moto data.
    rest_api: RestApi
    # maps AuthorizerId -> Authorizer
    authorizers: Dict[str, Authorizer]
    # maps RequestValidatorId -> RequestValidator
    validators: Dict[str, RequestValidator]
    # map DocumentationPartId -> DocumentationPart
    documentation_parts: Dict[str, DocumentationPart]
    # not used yet, still in moto
    gateway_responses: Dict[str, GatewayResponse]
    # maps Model name -> Model
    models: Dict[str, Model]
    # maps Model name -> resolved dict Model, so we don't need to load the JSON everytime
    resolved_models: Dict[str, dict]
    # maps ResourceId of a Resource to its children ResourceIds
    resource_children: Dict[str, List[str]]

    def __init__(self, rest_api: RestApi):
        self.rest_api = rest_api
        self.authorizers = {}
        self.validators = {}
        self.documentation_parts = {}
        self.gateway_responses = {}
        self.models = {}
        self.resolved_models = {}
        self.resource_children = {}


class ApiGatewayStore(BaseStore):
    # maps (API id) -> RestApiContainer
    # TODO: remove CaseInsensitiveDict, and lower the value of the ID when getting it from the tags
    rest_apis: Dict[str, RestApiContainer] = LocalAttribute(default=CaseInsensitiveDict)

    # account details
    account: Dict[str, Any] = LocalAttribute(default=dict)

    # maps (domain_name) -> [path_mappings]
    base_path_mappings: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # maps ID to VPC link details
    vpc_links: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps cert ID to client certificate details
    client_certificates: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps resource ARN to tags
    TAGS: Dict[str, Dict[str, str]] = CrossRegionAttribute(default=dict)

    def __init__(self):
        super().__init__()

        self.account.update(
            {
                "cloudwatchRoleArn": arns.role_arn("api-gw-cw-role"),
                "throttleSettings": {"burstLimit": 1000, "rateLimit": 500},
                "features": ["UsagePlans"],
                "apiKeyVersion": "1",
            }
        )


apigateway_stores = AccountRegionBundle("apigateway", ApiGatewayStore)


class PayloadFormatVersion(Enum):
    V1 = "1.0"
    V2 = "2.0"

    @staticmethod
    def is_v1(integration: Dict[str, Any]) -> bool:
        return (
            "payloadFormatVersion" not in integration
            or PayloadFormatVersion(integration["payloadFormatVersion"]) == PayloadFormatVersion.V1
        )

    @staticmethod
    def is_v2_payload_format_version(integration: Dict[str, Any]) -> bool:
        return (
            integration is not None
            and "payloadFormatVersion" in integration
            and PayloadFormatVersion(integration["payloadFormatVersion"]) == PayloadFormatVersion.V2
        )

    @staticmethod
    def is_v2_authorizer_payload_format_version(authorizer_config: Dict[str, Any]) -> bool:
        """
        If we don't specify a payload format version, the AWS Management Console uses the latest
        version by default
        """
        return (
            "authorizerPayloadFormatVersion" not in authorizer_config
            or PayloadFormatVersion(authorizer_config["authorizerPayloadFormatVersion"])
            == PayloadFormatVersion.V2
        )


class ApiGatewayVersion(Enum):
    V1 = "v1"
    V2 = "v2"


class ApiInvocationContext:
    """Represents the context for an incoming API Gateway invocation."""

    # basic (raw) HTTP invocation details (method, path, data, headers)
    method: str
    path: str
    data: InvocationPayload
    headers: Dict[str, str]

    # invocation context
    context: Dict[str, Any]
    # authentication info for this invocation
    auth_context: Dict[str, Any]

    # target API/resource details extracted from the invocation
    apigw_version: ApiGatewayVersion
    payload_format_version: PayloadFormatVersion
    api_id: str
    stage: str
    account_id: str
    region_name: str
    # resource path, including any path parameter placeholders (e.g., "/my/path/{id}")
    resource_path: str
    integration: Dict
    resource: Dict
    # Invocation path with query string, e.g., "/my/path?test". Defaults to "path", can be used
    #  to overwrite the actual API path, in case the path format "../_user_request_/.." is used.
    _path_with_query_string: str

    # response templates to be applied to the invocation result
    response_templates: Dict

    route: Dict
    connection_id: str
    path_params: Dict

    # response object
    response: Response

    # dict of stage variables (mapping names to values)
    stage_variables: Dict[str, str]

    # websockets route selection
    ws_route: str

    def __init__(
        self,
        method: str,
        path: str,
        data: Union[str, bytes],
        headers: Dict[str, str],
        api_id: str = None,
        stage: str = None,
        context: Dict[str, Any] = None,
        auth_context: Dict[str, Any] = None,
    ):
        self.method = method
        self.path = path
        self.data = data
        self.headers = headers
        self.context = {"requestId": short_uid()} if context is None else context
        self.auth_context = {} if auth_context is None else auth_context
        self.apigw_version = None
        self.api_id = api_id
        self.stage = stage
        self.region_name = None
        self.account_id = None
        self.integration = None
        self.resource = None
        self.resource_path = None
        self.path_with_query_string = None
        self.response_templates = {}
        self.stage_variables = {}
        self.path_params = {}
        self.route = None
        self.ws_route = None
        self.response = None
        self.payload_format_version = PayloadFormatVersion.V1

    @property
    def resource_id(self) -> Optional[str]:
        return (self.resource or {}).get("id")

    @property
    def invocation_path(self) -> str:
        """Return the plain invocation path, without query parameters."""
        path = self.path_with_query_string or self.path
        return path.split("?")[0]

    @property
    def path_with_query_string(self) -> str:
        """Return invocation path with query string - defaults to the value of 'path', unless customized."""
        return self._path_with_query_string or self.path

    @path_with_query_string.setter
    def path_with_query_string(self, new_path: str):
        """Set a custom invocation path with query string (used to handle "../_user_request_/.." paths)."""
        self._path_with_query_string = new_path

    def query_params(self) -> Dict[str, str]:
        """Extract the query parameters from the target URL or path in this request context."""
        query_string = self.path_with_query_string.partition("?")[2]
        return parse_query_string(query_string)

    @property
    def integration_uri(self) -> Optional[str]:
        integration = self.integration or {}
        return integration.get("uri") or integration.get("integrationUri")

    @property
    def auth_identity(self) -> Optional[Dict]:
        if isinstance(self.auth_context, dict):
            if self.auth_context.get("identity") is None:
                self.auth_context["identity"] = {}
            return self.auth_context["identity"]

    @property
    def authorizer_type(self) -> str:
        if isinstance(self.auth_context, dict):
            return self.auth_context.get("authorizer_type") if self.auth_context else None

    @property
    def authorizer_result(self) -> Dict[str, Any]:
        if isinstance(self.auth_context, dict):
            return self.auth_context.get("authorizer") if self.auth_context else {}

    def is_websocket_request(self) -> bool:
        upgrade_header = str(self.headers.get("upgrade") or "")
        return upgrade_header.lower() == "websocket"

    def is_v1(self) -> bool:
        """Whether this is an API Gateway v1 request"""
        return self.apigw_version == ApiGatewayVersion.V1

    def cookies(self) -> Optional[List[str]]:
        if cookies := self.headers.get("cookie") or "":
            return list(cookies.split(";"))
        return None

    @property
    def is_data_base64_encoded(self) -> bool:
        try:
            json.dumps(self.data) if isinstance(self.data, (dict, list)) else to_str(self.data)
            return False
        except UnicodeDecodeError:
            return True

    def data_as_string(self) -> str:
        try:
            return (
                json.dumps(self.data) if isinstance(self.data, (dict, list)) else to_str(self.data)
            )
        except UnicodeDecodeError:
            # we string encode our base64 as string as well
            return to_str(base64.b64encode(self.data))

    def _extract_host_from_header(self) -> str:
        host = self.headers.get(HEADER_LOCALSTACK_EDGE_URL) or self.headers.get("host", "")
        return host.split("://")[-1].split("/")[0].split(":")[0]

    @property
    def domain_name(self) -> str:
        return self._extract_host_from_header()

    @property
    def domain_prefix(self) -> str:
        host = self._extract_host_from_header()
        return host.split(".")[0]

    def is_payload_v2(self):
        return self.payload_format_version.is_v2_payload_format_version(self.integration)


class BaseHeadersSerializer:
    """
    Helper class to correctly serialize headers and cookies for Amazon API Gateway,
    ALB and Lambda Function URL response payload.
    """

    def serialize(
        self, headers: Dict[str, Union[str, List[str]]], cookies: List[Cookie]
    ) -> Dict[str, Any]:
        """
        Serializes headers and cookies according to the request type.
        Returns a dict that can be merged with the response payload.
        Parameters
        ----------
        headers: Dict[str, List[str]]
            A dictionary of headers to set in the response
        cookies: List[str]
            A list of cookies to set in the response
        """
        raise NotImplementedError()


class HttpApiHeadersSerializer(BaseHeadersSerializer):
    def serialize(
        self, headers: Dict[str, Union[str, List[str]]], cookies: List[Cookie]
    ) -> Dict[str, Any]:
        """
        When using HTTP APIs or LambdaFunctionURLs, everything is taken care automatically for us.
        We can directly assign a list of cookies and a dict of headers to the response payload, and the
        runtime will automatically serialize them correctly on the output.
        https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html#http-api-develop-integrations-lambda.proxy-format
        https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html#http-api-develop-integrations-lambda.response
        """

        # Format 2.0 doesn't have multiValueHeaders or multiValueQueryStringParameters fields.
        # Duplicate headers are combined with commas and included in the headers field.
        combined_headers: Dict[str, str] = {}
        for key, values in headers.items():
            # omit headers with explicit null values
            if values is None:
                continue

            if isinstance(values, str):
                combined_headers[key] = values
            else:
                combined_headers[key] = ", ".join(values)

        return {"headers": combined_headers, "cookies": list(map(str, cookies))}


class MultiValueHeadersSerializer(BaseHeadersSerializer):
    def serialize(
        self, headers: Dict[str, Union[str, List[str]]], cookies: List[Cookie]
    ) -> Dict[str, Any]:
        """
        When using REST APIs, headers can be encoded using the `multiValueHeaders` key on the response.
        This is also the case when using an ALB integration with the `multiValueHeaders` option enabled.
        The solution covers headers with just one key or multiple keys.
        https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-output-format
        https://docs.aws.amazon.com/elasticloadbalancing/latest/application/lambda-functions.html#multi-value-headers-response
        """
        payload: Dict[str, List[str]] = defaultdict(list)
        for key, values in headers.items():
            # omit headers with explicit null values
            if values is None:
                continue

            if isinstance(values, str):
                payload[key].append(values)
            else:
                payload[key].extend(values)

        if cookies:
            payload.setdefault("Set-Cookie", [])
            for cookie in cookies:
                payload["Set-Cookie"].append(str(cookie))

        return {"multiValueHeaders": payload}


class RequestContextClientCert:
    client_cert_pem: str
    issuer_dn: str
    serial_number: str
    subject_dn: str
    validity_not_after: str
    validity_not_before: str


class APIGatewayEventIdentity:
    access_key: Optional[str]
    account_id: Optional[str]
    api_key: Optional[str]
    caller: Optional[str]
    cognito_authentication_provider: Optional[str]
    cognito_authentication_type: Optional[str]
    cognito_identity_id: Optional[str]
    cognito_identity_pool_id: Optional[str]
    cognito_amr: Optional[List[str]]
    principal_org_id: Optional[str]
    source_ip: str
    user: Optional[str]
    user_agent: Optional[str]
    user_arn: Optional[str]
    client_cert: Optional[RequestContextClientCert]


class RequestContextAuthorizer:
    claims: Optional[Dict[str, Any]]
    scopes: Optional[List[str]]
    principal_id: Optional[str]
    integration_latency: Optional[int]


class BaseRequestContext:

    path: str
    stage: str
    api_id: str
    account_id: str
    request_id: str
    http_method: str
    resource_id: str
    resource_path: str
    identity: APIGatewayEventIdentity
    domain_name: Optional[str]
    request_time: Optional[str]
    domain_prefix: Optional[str]
    request_time_epoch: Optional[int]
    extended_request_id: Optional[str]


class RequestContext(BaseRequestContext):

    connected_at: Optional[int]
    connection_id: Optional[str]
    event_type: Optional[str]
    message_direction: Optional[str]
    message_id: Optional[str]
    operation_name: Optional[str]
    route_key: Optional[str]
    authorizer: RequestContextAuthorizer


class BaseProxyEvent:

    headers: Dict[str, str]
    query_string_parameters: Optional[Dict[str, str]]
    is_base64_encoded: Optional[bool]
    body: Optional[str]
    path: str
    http_method: str

    def get_query_string_value(
        self, name: str, default_value: Optional[str] = None
    ) -> Optional[str]:
        """Get query string value by name
        Parameters
        ----------
        name: str
            Query string parameter name
        default_value: str, optional
            Default value if no value was found by name
        Returns
        -------
        str, optional
            Query string parameter value
        """
        params = self.query_string_parameters
        return default_value if params is None else params.get(name, default_value)


class APIGatewayProxyEventEncoder(json.JSONEncoder):
    def default(self, o):
        if o is None:
            return None

        if isinstance(
            o,
            (
                APIGatewayProxyEvent,
                RequestContext,
                APIGatewayEventIdentity,
                RequestContextAuthorizer,
                RequestContextClientCert,
                APIGatewayProxyEventV2,
                RequestContextV2,
                BaseRequestContextV2,
                RequestContextV2Authorizer,
                RequestContextV2AuthorizerIam,
                RequestContextV2Http,
                dict,
            ),
        ):
            return {snake_to_camel(k): v for k, v in o.__dict__.items()}
        return json.JSONEncoder.default(self, o)


class APIGatewayProxyEvent(BaseProxyEvent):
    """AWS Lambda proxy V1
    Documentation:
    --------------
    - https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    """

    version: str
    resource: str
    multi_value_headers: Dict[str, List[str]]
    multi_value_query_string_parameters: Dict[str, List[str]]
    request_context: RequestContext
    stage_variables: Dict[str, str]

    def header_serializer(self) -> BaseHeadersSerializer:
        return MultiValueHeadersSerializer()

    def to_json(self) -> str:
        return json.dumps(self, cls=APIGatewayProxyEventEncoder)


class RequestContextV2Http:
    method: str
    path: str
    protocol: str
    source_ip: str
    user_agent: str


class BaseRequestContextV2:
    account_id: str
    api_id: str
    domain_name: str
    domain_prefix: str
    http: RequestContextV2Http
    request_id: str
    route_key: str
    stage: str
    time: str
    time_epoch: int
    authentication: Optional[RequestContextClientCert]


class RequestContextV2AuthorizerIam:
    access_key: Optional[str]
    account_id: Optional[str]
    caller_id: Optional[str]
    cognito_amr: Optional[List[str]]
    cognito_identity_id: Optional[str]
    cognito_identity_pool_id: Optional[str]
    principal_org_id: Optional[str]
    user_arn: Optional[str]
    user_id: Optional[str]
    cognito_identity: Optional[Dict[str, Any]]


class RequestContextV2Authorizer:
    jwt: Optional[Dict[str, Any]]
    custom: Optional[Dict[str, Any]]
    iam: Optional[RequestContextV2AuthorizerIam]

    @property
    def jwt_claim(self) -> Optional[Dict[str, Any]]:
        jwt = self.jwt or {}  # not available in FunctionURL
        return jwt.get("claims")

    @property
    def jwt_scopes(self) -> Optional[List[str]]:
        jwt = self.jwt or {}  # not available in FunctionURL
        return jwt.get("scopes")

    @property
    def get_lambda(self) -> Optional[Dict[str, Any]]:
        """Lambda authorization context details"""
        return self.custom

    @property
    def iam_auth(self) -> Optional[RequestContextV2AuthorizerIam]:
        """IAM authorization details used for making the request."""
        return self.iam or None


class RequestContextV2(BaseRequestContextV2):
    authorizer: Optional[RequestContextV2Authorizer]


class APIGatewayProxyEventV2(BaseProxyEvent):
    """AWS Lambda proxy V2 event
    Notes:
    -----
    Format 2.0 doesn't have multiValueHeaders or multiValueQueryStringParameters fields. Duplicate headers
    are combined with commas and included in the headers field. Duplicate query strings are combined with
    commas and included in the queryStringParameters field.
    Format 2.0 includes a new cookies field. All cookie headers in the request are combined with commas and
    added to the cookies field. In the response to the client, each cookie becomes a set-cookie header.
    Documentation:
    --------------
    - https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    """

    version = str
    route_key = str
    raw_path = str
    raw_query_string = str
    cookies = Optional[List[str]]
    path_parameters = Optional[Dict[str, str]]
    stage_variables = Optional[Dict[str, str]]
    request_context = RequestContextV2

    @property
    def path(self) -> str:
        stage = self.request_context.stage
        if stage != "$default":
            return self.raw_path[len(f"/{stage}") :]
        return self.raw_path

    @property
    def http_method(self) -> str:
        """The HTTP method used. Valid values include: DELETE, GET, HEAD, OPTIONS, PATCH, POST, and PUT."""
        return self.request_context.http.method

    def header_serializer(self):
        return HttpApiHeadersSerializer()

    def to_json(self) -> str:
        return json.dumps(self, cls=APIGatewayProxyEventEncoder)
