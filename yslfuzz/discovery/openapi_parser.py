"""Minimal OpenAPI 3.x parser for YSLFuzz discovery."""

from collections.abc import Mapping
from hashlib import sha256
from json import JSONDecodeError
import json
from pathlib import Path
from typing import Any

import yaml

from yslfuzz.models.auth import AuthScheme
from yslfuzz.models.base import prefixed_id
from yslfuzz.models.enums import (
    ApiStyle,
    AuthType,
    ConstraintType,
    FieldType,
    HttpMethod,
    ParameterLocation,
)
from yslfuzz.models.schema import (
    ApiSchema,
    Constraint,
    Endpoint,
    FieldDefinition,
    Parameter,
    RequestBodyDefinition,
    ResponseDefinition,
    SchemaSource,
    TypeReference,
)


class OpenAPIParseError(ValueError):
    """Raised when an OpenAPI document cannot be parsed by the MVP parser."""


class OpenAPIParser:
    """Parse OpenAPI 3.x dictionaries or local files into an internal ApiSchema."""

    supported_methods: dict[str, HttpMethod] = {
        "get": HttpMethod.GET,
        "post": HttpMethod.POST,
        "put": HttpMethod.PUT,
        "patch": HttpMethod.PATCH,
        "delete": HttpMethod.DELETE,
    }

    def parse(self, source: Mapping[str, Any] | str | Path) -> ApiSchema:
        document, source_location, raw_content_hash = self._load_source(source)
        self._validate_document(document)

        api_schema_id = prefixed_id("api_schema")
        info = self._expect_mapping(document.get("info"), "OpenAPI document info")
        base_url = self._extract_base_url(document)
        global_security = document.get("security")
        auth_schemes = self._parse_auth_schemes(document)

        schema_source = SchemaSource(
            source_type="OPENAPI_FILE" if source_location != "<dict>" else "MANUAL",
            location=source_location,
            api_style=ApiStyle.REST,
            raw_content_hash=raw_content_hash,
            parser_version="0.1.0",
        )

        endpoints = self._parse_endpoints(
            document=document,
            api_schema_id=api_schema_id,
            global_security=global_security,
        )

        return ApiSchema(
            api_schema_id=api_schema_id,
            target_id="target_unset",
            title=self._optional_string(info.get("title")),
            version=self._optional_string(info.get("version")),
            api_style=ApiStyle.REST,
            base_url=base_url,
            endpoints=endpoints,
            auth_schemes=auth_schemes,
            created_from=[schema_source],
        )

    def _load_source(self, source: Mapping[str, Any] | str | Path) -> tuple[dict[str, Any], str, str | None]:
        if isinstance(source, Mapping):
            return dict(source), "<dict>", self._hash_mapping(source)

        path = Path(source)
        if not path.exists():
            raise OpenAPIParseError(f"OpenAPI file does not exist: {path}")
        if not path.is_file():
            raise OpenAPIParseError(f"OpenAPI source is not a file: {path}")

        raw_content = path.read_text(encoding="utf-8")
        try:
            if path.suffix.lower() == ".json":
                loaded = json.loads(raw_content)
            elif path.suffix.lower() in {".yaml", ".yml"}:
                loaded = yaml.safe_load(raw_content)
            else:
                raise OpenAPIParseError(
                    f"Unsupported OpenAPI file extension '{path.suffix}'. Use .yaml, .yml, or .json"
                )
        except (JSONDecodeError, yaml.YAMLError) as exc:
            raise OpenAPIParseError(f"Could not parse OpenAPI file {path}: {exc}") from exc

        if not isinstance(loaded, dict):
            raise OpenAPIParseError("OpenAPI file must contain a mapping/object document")

        return loaded, str(path), sha256(raw_content.encode("utf-8")).hexdigest()

    def _validate_document(self, document: Mapping[str, Any]) -> None:
        openapi_version = document.get("openapi")
        if not isinstance(openapi_version, str) or not openapi_version.startswith("3."):
            raise OpenAPIParseError("Only OpenAPI 3.x documents are supported")
        if not isinstance(document.get("info"), Mapping):
            raise OpenAPIParseError("OpenAPI document must contain an info object")
        if not isinstance(document.get("paths"), Mapping):
            raise OpenAPIParseError("OpenAPI document must contain a paths object")

    def _extract_base_url(self, document: Mapping[str, Any]) -> str:
        servers = document.get("servers")
        if isinstance(servers, list) and servers:
            first_server = servers[0]
            if isinstance(first_server, Mapping) and isinstance(first_server.get("url"), str):
                return str(first_server["url"])
        return ""

    def _parse_endpoints(
        self,
        document: Mapping[str, Any],
        api_schema_id: str,
        global_security: Any,
    ) -> list[Endpoint]:
        paths = self._expect_mapping(document.get("paths"), "OpenAPI paths")
        endpoints: list[Endpoint] = []

        for path, path_item_raw in paths.items():
            if not isinstance(path, str):
                raise OpenAPIParseError("OpenAPI path keys must be strings")
            path_item = self._expect_mapping(path_item_raw, f"path item for {path}")
            path_parameters = self._parse_parameters(path_item.get("parameters", []), document)

            for method_name, operation_raw in path_item.items():
                method = self.supported_methods.get(method_name.lower())
                if method is None:
                    continue
                operation = self._expect_mapping(operation_raw, f"operation {method_name.upper()} {path}")
                operation_parameters = self._parse_parameters(operation.get("parameters", []), document)
                request_body = self._parse_request_body(operation.get("requestBody"), document)
                responses = self._parse_responses(operation.get("responses"), document)
                security = operation.get("security", global_security)

                endpoints.append(
                    Endpoint(
                        api_schema_id=api_schema_id,
                        name=self._endpoint_name(method, path, operation),
                        api_style=ApiStyle.REST,
                        path=path,
                        method=method,
                        summary=self._optional_string(operation.get("summary")),
                        description=self._optional_string(operation.get("description")),
                        auth_required=self._security_requires_auth(security),
                        deprecated=bool(operation.get("deprecated", False)),
                        parameters=[*path_parameters, *operation_parameters],
                        request_body=request_body,
                        responses=responses,
                        tags=[
                            tag
                            for tag in operation.get("tags", [])
                            if isinstance(tag, str)
                        ],
                    )
                )

        return endpoints

    def _parse_parameters(self, parameters_raw: Any, document: Mapping[str, Any]) -> list[Parameter]:
        if parameters_raw is None:
            return []
        if not isinstance(parameters_raw, list):
            raise OpenAPIParseError("OpenAPI parameters must be a list")

        parameters: list[Parameter] = []
        for parameter_raw in parameters_raw:
            parameter = self._resolve_ref(parameter_raw, document)
            parameter_mapping = self._expect_mapping(parameter, "OpenAPI parameter")
            name = self._required_string(parameter_mapping.get("name"), "parameter name")
            location = self._parameter_location(parameter_mapping.get("in"))
            schema = self._schema_mapping(parameter_mapping.get("schema"), document)
            field_type = self._field_type(schema)

            parameters.append(
                Parameter(
                    name=name,
                    location=location,
                    field_type=field_type,
                    required=bool(parameter_mapping.get("required", location == ParameterLocation.PATH)),
                    constraints=self._constraints(schema),
                    default_value=schema.get("default"),
                    example_value=parameter_mapping.get("example", schema.get("example")),
                    description=self._optional_string(parameter_mapping.get("description")),
                    sensitive=self._is_sensitive_name(name),
                )
            )

        return parameters

    def _parse_request_body(
        self,
        request_body_raw: Any,
        document: Mapping[str, Any],
    ) -> RequestBodyDefinition | None:
        if request_body_raw is None:
            return None
        request_body = self._expect_mapping(
            self._resolve_ref(request_body_raw, document),
            "OpenAPI requestBody",
        )
        media_type = self._json_media_type(request_body)
        if media_type is None:
            return None
        schema = self._schema_mapping(media_type.get("schema"), document)

        return RequestBodyDefinition(
            content_type="application/json",
            required=bool(request_body.get("required", False)),
            root_type=TypeReference(name=schema.get("title"), field_type=self._field_type(schema)),
            fields=self._fields_from_schema(schema, document, root_name="body"),
        )

    def _parse_responses(
        self,
        responses_raw: Any,
        document: Mapping[str, Any],
    ) -> list[ResponseDefinition]:
        if responses_raw is None:
            return []
        responses = self._expect_mapping(responses_raw, "OpenAPI responses")
        definitions: list[ResponseDefinition] = []

        for status_code, response_raw in responses.items():
            response = self._expect_mapping(
                self._resolve_ref(response_raw, document),
                f"OpenAPI response {status_code}",
            )
            media_type = self._json_media_type(response)
            schema = self._schema_mapping(media_type.get("schema"), document) if media_type else {}
            definitions.append(
                ResponseDefinition(
                    status_code=int(status_code) if str(status_code).isdigit() else str(status_code),
                    description=self._optional_string(response.get("description")),
                    content_type="application/json" if media_type else None,
                    body_type=TypeReference(name=schema.get("title"), field_type=self._field_type(schema))
                    if schema
                    else None,
                    fields=self._fields_from_schema(schema, document, root_name="response")
                    if schema
                    else [],
                )
            )

        return definitions

    def _parse_auth_schemes(self, document: Mapping[str, Any]) -> list[AuthScheme]:
        components = document.get("components")
        if not isinstance(components, Mapping):
            return []
        security_schemes = components.get("securitySchemes")
        if not isinstance(security_schemes, Mapping):
            return []

        auth_schemes: list[AuthScheme] = []
        for name, scheme_raw in security_schemes.items():
            if not isinstance(name, str):
                continue
            scheme = self._expect_mapping(scheme_raw, f"security scheme {name}")
            auth_type = self._auth_type(scheme)
            location = self._security_location(scheme)
            auth_schemes.append(
                AuthScheme(
                    auth_type=auth_type,
                    name=name,
                    location=location,
                    header_name=scheme.get("name") if location == ParameterLocation.HEADER else None,
                    query_param_name=scheme.get("name") if location == ParameterLocation.QUERY else None,
                    cookie_name=scheme.get("name") if location == ParameterLocation.COOKIE else None,
                    description=self._optional_string(scheme.get("description")),
                )
            )

        return auth_schemes

    def _fields_from_schema(
        self,
        schema_raw: Mapping[str, Any],
        document: Mapping[str, Any],
        root_name: str,
    ) -> list[FieldDefinition]:
        schema = self._schema_mapping(schema_raw, document)
        field_type = self._field_type(schema)
        if field_type == FieldType.OBJECT:
            required_fields = self._string_list(schema.get("required"))
            properties = schema.get("properties", {})
            if not isinstance(properties, Mapping):
                return []
            return [
                self._field_from_schema(name, child_schema, document, required_fields)
                for name, child_schema in properties.items()
                if isinstance(name, str)
            ]
        return [self._field_from_schema(root_name, schema, document, [])]

    def _field_from_schema(
        self,
        name: str,
        schema_raw: Any,
        document: Mapping[str, Any],
        required_fields: list[str],
    ) -> FieldDefinition:
        schema = self._schema_mapping(schema_raw, document)
        field_type = self._field_type(schema)
        nested_fields: list[FieldDefinition] = []
        array_item_type: TypeReference | None = None

        if field_type == FieldType.OBJECT:
            child_required_fields = self._string_list(schema.get("required"))
            properties = schema.get("properties", {})
            if isinstance(properties, Mapping):
                nested_fields = [
                    self._field_from_schema(child_name, child_schema, document, child_required_fields)
                    for child_name, child_schema in properties.items()
                    if isinstance(child_name, str)
                ]
        elif field_type == FieldType.ARRAY:
            items = self._schema_mapping(schema.get("items"), document)
            array_item_type = TypeReference(name=items.get("title"), field_type=self._field_type(items))
            if self._field_type(items) == FieldType.OBJECT:
                nested_fields = self._fields_from_schema(items, document, root_name=name)

        return FieldDefinition(
            name=name,
            field_type=field_type,
            required=name in required_fields,
            nullable=bool(schema.get("nullable", False)),
            read_only=bool(schema.get("readOnly", False)),
            write_only=bool(schema.get("writeOnly", False)),
            sensitive=self._is_sensitive_name(name),
            constraints=self._constraints(schema),
            nested_fields=nested_fields,
            array_item_type=array_item_type,
            description=self._optional_string(schema.get("description")),
            example_value=schema.get("example"),
        )

    def _constraints(self, schema: Mapping[str, Any]) -> list[Constraint]:
        constraint_map: tuple[tuple[str, ConstraintType], ...] = (
            ("minLength", ConstraintType.MIN_LENGTH),
            ("maxLength", ConstraintType.MAX_LENGTH),
            ("minimum", ConstraintType.MIN_VALUE),
            ("maximum", ConstraintType.MAX_VALUE),
            ("enum", ConstraintType.ENUM),
            ("format", ConstraintType.FORMAT),
            ("nullable", ConstraintType.NULLABLE),
        )
        constraints: list[Constraint] = []
        for openapi_key, constraint_type in constraint_map:
            if openapi_key in schema:
                constraints.append(
                    Constraint(
                        constraint_type=constraint_type,
                        value=schema[openapi_key],
                        source="openapi",
                    )
                )
        return constraints

    def _field_type(self, schema: Mapping[str, Any]) -> FieldType:
        if "enum" in schema:
            return FieldType.ENUM

        schema_type = schema.get("type")
        schema_format = schema.get("format")
        if schema_type == "string":
            string_format = schema_format if isinstance(schema_format, str) else None
            if string_format is None:
                return FieldType.STRING
            return {
                "email": FieldType.EMAIL,
                "uuid": FieldType.UUID,
                "uri": FieldType.URI,
                "url": FieldType.URI,
                "date": FieldType.DATE,
                "date-time": FieldType.DATETIME,
            }.get(string_format, FieldType.STRING)
        if schema_type == "integer":
            return FieldType.INTEGER
        if schema_type == "number":
            return FieldType.FLOAT
        if schema_type == "boolean":
            return FieldType.BOOLEAN
        if schema_type == "object" or "properties" in schema:
            return FieldType.OBJECT
        if schema_type == "array":
            return FieldType.ARRAY
        return FieldType.UNKNOWN

    def _schema_mapping(self, schema_raw: Any, document: Mapping[str, Any]) -> dict[str, Any]:
        if schema_raw is None:
            return {}
        resolved = self._resolve_ref(schema_raw, document)
        schema = self._expect_mapping(resolved, "OpenAPI schema")
        return dict(schema)

    def _resolve_ref(self, value: Any, document: Mapping[str, Any]) -> Any:
        if not isinstance(value, Mapping) or "$ref" not in value:
            return value
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise OpenAPIParseError(f"Unsupported $ref '{ref}'. Only local refs are supported")

        current: Any = document
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, Mapping) or part not in current:
                raise OpenAPIParseError(f"Could not resolve local $ref '{ref}'")
            current = current[part]
        return current

    def _json_media_type(self, value: Mapping[str, Any]) -> Mapping[str, Any] | None:
        content = value.get("content")
        if not isinstance(content, Mapping):
            return None
        media_type = content.get("application/json")
        if isinstance(media_type, Mapping):
            return media_type
        return None

    def _parameter_location(self, raw_location: Any) -> ParameterLocation:
        if raw_location == "path":
            return ParameterLocation.PATH
        if raw_location == "query":
            return ParameterLocation.QUERY
        if raw_location == "header":
            return ParameterLocation.HEADER
        if raw_location == "cookie":
            return ParameterLocation.COOKIE
        raise OpenAPIParseError(f"Unsupported parameter location: {raw_location}")

    def _auth_type(self, scheme: Mapping[str, Any]) -> AuthType:
        scheme_type = scheme.get("type")
        if scheme_type == "apiKey":
            return AuthType.API_KEY
        if scheme_type == "http":
            http_scheme = scheme.get("scheme")
            bearer_format = scheme.get("bearerFormat")
            if http_scheme == "basic":
                return AuthType.BASIC
            if http_scheme == "bearer" and bearer_format == "JWT":
                return AuthType.JWT
            if http_scheme == "bearer":
                return AuthType.BEARER
        if scheme_type == "oauth2":
            return AuthType.OAUTH2
        return AuthType.CUSTOM

    def _security_location(self, scheme: Mapping[str, Any]) -> ParameterLocation | None:
        location = scheme.get("in")
        if location == "header":
            return ParameterLocation.HEADER
        if location == "query":
            return ParameterLocation.QUERY
        if location == "cookie":
            return ParameterLocation.COOKIE
        return None

    def _security_requires_auth(self, security: Any) -> bool:
        if security is None:
            return False
        if isinstance(security, list):
            return bool(security)
        return False

    def _endpoint_name(
        self,
        method: HttpMethod,
        path: str,
        operation: Mapping[str, Any],
    ) -> str:
        operation_id = operation.get("operationId")
        if isinstance(operation_id, str) and operation_id:
            return operation_id
        normalized_path = path.strip("/").replace("/", "_").replace("{", "").replace("}", "")
        return f"{method.value.lower()}_{normalized_path or 'root'}"

    def _expect_mapping(self, value: Any, label: str) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise OpenAPIParseError(f"{label} must be an object")
        return value

    def _required_string(self, value: Any, label: str) -> str:
        if not isinstance(value, str) or not value:
            raise OpenAPIParseError(f"{label} must be a non-empty string")
        return value

    def _optional_string(self, value: Any) -> str | None:
        return value if isinstance(value, str) else None

    def _string_list(self, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]

    def _is_sensitive_name(self, name: str) -> bool:
        normalized = name.lower().replace("-", "_")
        return any(
            token in normalized
            for token in ("authorization", "api_key", "apikey", "cookie", "password", "secret", "token")
        )

    def _hash_mapping(self, value: Mapping[str, Any]) -> str:
        encoded = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
        return sha256(encoded).hexdigest()
