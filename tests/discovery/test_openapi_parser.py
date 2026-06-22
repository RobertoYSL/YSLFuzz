from pathlib import Path

import pytest

from yslfuzz.discovery import DiscoveryManager, OpenAPIParseError, OpenAPIParser
from yslfuzz.models import (
    ApiStyle,
    AuthType,
    ConstraintType,
    FieldType,
    HttpMethod,
    ParameterLocation,
)


EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")


def test_parse_simple_users_api_from_yaml_file() -> None:
    api_schema = OpenAPIParser().parse(EXAMPLE_SCHEMA)

    assert api_schema.title == "Simple Users API"
    assert api_schema.version == "1.0.0"
    assert api_schema.api_style == ApiStyle.REST
    assert api_schema.base_url == "http://localhost:8000"
    assert api_schema.created_from[0].source_type == "OPENAPI_FILE"


def test_discovery_manager_parses_openapi() -> None:
    api_schema = DiscoveryManager().discover_openapi(EXAMPLE_SCHEMA)

    assert api_schema.title == "Simple Users API"


def test_endpoint_count_methods_and_auth_required() -> None:
    api_schema = OpenAPIParser().parse(EXAMPLE_SCHEMA)
    methods_by_name = {endpoint.name: endpoint.method for endpoint in api_schema.endpoints}
    auth_by_name = {endpoint.name: endpoint.auth_required for endpoint in api_schema.endpoints}

    assert len(api_schema.endpoints) == 3
    assert methods_by_name == {
        "listUsers": HttpMethod.GET,
        "createUser": HttpMethod.POST,
        "getUser": HttpMethod.GET,
    }
    assert auth_by_name == {
        "listUsers": True,
        "createUser": True,
        "getUser": False,
    }


def test_parameters_are_mapped() -> None:
    api_schema = OpenAPIParser().parse(EXAMPLE_SCHEMA)
    list_users = next(endpoint for endpoint in api_schema.endpoints if endpoint.name == "listUsers")
    get_user = next(endpoint for endpoint in api_schema.endpoints if endpoint.name == "getUser")

    limit = next(parameter for parameter in list_users.parameters if parameter.name == "limit")
    request_id = next(parameter for parameter in list_users.parameters if parameter.name == "X-Request-ID")
    user_id = next(parameter for parameter in get_user.parameters if parameter.name == "user_id")

    assert limit.location == ParameterLocation.QUERY
    assert limit.field_type == FieldType.INTEGER
    assert {constraint.constraint_type for constraint in limit.constraints} == {
        ConstraintType.MIN_VALUE,
        ConstraintType.MAX_VALUE,
    }
    assert request_id.location == ParameterLocation.HEADER
    assert request_id.field_type == FieldType.UUID
    assert user_id.location == ParameterLocation.PATH
    assert user_id.required is True


def test_request_body_fields_and_constraints_are_mapped() -> None:
    api_schema = OpenAPIParser().parse(EXAMPLE_SCHEMA)
    create_user = next(endpoint for endpoint in api_schema.endpoints if endpoint.name == "createUser")

    assert create_user.request_body is not None
    assert create_user.request_body.required is True
    fields = {field.name: field for field in create_user.request_body.fields}

    assert fields["email"].field_type == FieldType.EMAIL
    assert fields["email"].required is True
    assert fields["name"].field_type == FieldType.STRING
    assert fields["name"].required is True
    assert {constraint.constraint_type for constraint in fields["name"].constraints} == {
        ConstraintType.MIN_LENGTH,
        ConstraintType.MAX_LENGTH,
    }
    assert fields["role"].field_type == FieldType.ENUM
    assert any(
        constraint.constraint_type == ConstraintType.ENUM
        and constraint.value == ["user", "admin"]
        for constraint in fields["role"].constraints
    )
    assert fields["profile"].field_type == FieldType.OBJECT
    assert fields["profile"].nullable is True
    nested = {field.name: field for field in fields["profile"].nested_fields}
    assert nested["website"].field_type == FieldType.URI
    assert nested["birth_date"].field_type == FieldType.DATE


def test_response_definitions_are_mapped() -> None:
    api_schema = OpenAPIParser().parse(EXAMPLE_SCHEMA)
    list_users = next(endpoint for endpoint in api_schema.endpoints if endpoint.name == "listUsers")
    get_user = next(endpoint for endpoint in api_schema.endpoints if endpoint.name == "getUser")

    list_response = list_users.responses[0]
    get_response_codes = {response.status_code for response in get_user.responses}

    assert list_response.status_code == 200
    assert list_response.body_type is not None
    assert list_response.body_type.field_type == FieldType.ARRAY
    assert list_response.fields[0].field_type == FieldType.ARRAY
    assert list_response.fields[0].array_item_type is not None
    assert list_response.fields[0].array_item_type.field_type == FieldType.OBJECT
    assert get_response_codes == {200, 404}


def test_security_scheme_metadata_is_mapped() -> None:
    api_schema = OpenAPIParser().parse(EXAMPLE_SCHEMA)

    assert len(api_schema.auth_schemes) == 1
    auth_scheme = api_schema.auth_schemes[0]
    assert auth_scheme.auth_type == AuthType.API_KEY
    assert auth_scheme.name == "ApiKeyAuth"
    assert auth_scheme.location == ParameterLocation.HEADER
    assert auth_scheme.header_name == "X-API-Key"


def test_parse_from_loaded_dict() -> None:
    document = {
        "openapi": "3.0.3",
        "info": {"title": "Dict API", "version": "1.0.0"},
        "paths": {
            "/health": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "OK",
                        }
                    }
                }
            }
        },
    }

    api_schema = OpenAPIParser().parse(document)

    assert api_schema.title == "Dict API"
    assert api_schema.endpoints[0].path == "/health"
    assert api_schema.endpoints[0].method == HttpMethod.GET
    assert api_schema.created_from[0].source_type == "MANUAL"


@pytest.mark.parametrize(
    "document, message",
    [
        ({}, "Only OpenAPI 3.x documents are supported"),
        ({"openapi": "2.0", "info": {}, "paths": {}}, "Only OpenAPI 3.x documents are supported"),
        ({"openapi": "3.0.3", "paths": {}}, "info object"),
        ({"openapi": "3.0.3", "info": {}}, "paths object"),
    ],
)
def test_rejects_invalid_openapi_documents(document: dict[str, object], message: str) -> None:
    with pytest.raises(OpenAPIParseError, match=message):
        OpenAPIParser().parse(document)


def test_rejects_remote_or_missing_file_path() -> None:
    with pytest.raises(OpenAPIParseError, match="does not exist"):
        OpenAPIParser().parse("https://example.com/openapi.yaml")
