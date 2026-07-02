"""Map discovered GraphQL schemas into YSLFuzz ApiSchema models."""

from hashlib import sha256

from yslfuzz.discovery.graphql.models import (
    GraphQLArgument,
    GraphQLEnum,
    GraphQLInputObject,
    GraphQLOperation,
    GraphQLSchema,
    GraphQLType,
    GraphQLTypeKind,
    GraphQLTypeRef,
)
from yslfuzz.models.base import prefixed_id
from yslfuzz.models.enums import (
    ApiStyle,
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
    ResponseDefinition,
    SchemaSource,
    TypeDefinition,
    TypeReference,
)


class GraphQLToApiSchemaMapper:
    """Convert local GraphQL discovery models into the internal ApiSchema model."""

    def map(self, schema: GraphQLSchema, base_url: str | None = None) -> ApiSchema:
        """Map a GraphQLSchema to a YSLFuzz ApiSchema without enabling execution."""
        api_schema_id = prefixed_id("api_schema")
        source_type = (
            "GRAPHQL_INTROSPECTION"
            if schema.source_format == "introspection_json"
            else "GRAPHQL_SCHEMA_FILE"
        )
        source_location = schema.source_location or "<memory>"
        return ApiSchema(
            api_schema_id=api_schema_id,
            target_id="target_unset",
            title="GraphQL Schema",
            version=None,
            api_style=ApiStyle.GRAPHQL,
            base_url=base_url or "",
            endpoints=[
                self._operation_to_endpoint(operation, schema, api_schema_id)
                for operation in schema.operations
            ],
            types=self._types(schema),
            created_from=[
                SchemaSource(
                    source_type=source_type,
                    location=source_location,
                    api_style=ApiStyle.GRAPHQL,
                    raw_content_hash=self._stable_schema_hash(schema),
                    parser_version="0.1.0",
                    metadata={
                        "graphql_schema_id": schema.schema_id,
                        "graphql_source_format": schema.source_format,
                    },
                )
            ],
            metadata={
                "api_style": "graphql",
                "graphql_schema_id": schema.schema_id,
                "graphql_source_format": schema.source_format,
            },
        )

    def _operation_to_endpoint(
        self,
        operation: GraphQLOperation,
        schema: GraphQLSchema,
        api_schema_id: str,
    ) -> Endpoint:
        argument_metadata = [self._argument_metadata(argument) for argument in operation.arguments]
        return Endpoint(
            api_schema_id=api_schema_id,
            name=f"{operation.operation_type.value}.{operation.name}",
            api_style=ApiStyle.GRAPHQL,
            path="/graphql",
            method=HttpMethod.POST,
            graphql_operation_type=operation.operation_type.value,
            graphql_operation_name=operation.name,
            description=operation.description,
            parameters=[
                Parameter(
                    name=argument.name,
                    location=ParameterLocation.GRAPHQL_ARGUMENT,
                    field_type=self._field_type(argument.type_ref, schema),
                    required=argument.type_ref.is_non_null(),
                    constraints=self._constraints(argument.type_ref, schema),
                    description=argument.description,
                )
                for argument in operation.arguments
            ],
            responses=[
                ResponseDefinition(
                    status_code=200,
                    description="GraphQL operation result type discovered from local schema",
                    content_type="application/json",
                    body_type=TypeReference(
                        name=operation.type_ref.named_type(),
                        field_type=self._field_type(operation.type_ref, schema),
                    ),
                    metadata={"graphql_return_type": operation.type_ref.display()},
                )
            ],
            tags=["graphql", operation.operation_type.value],
            metadata={
                "api_style": "graphql",
                "graphql_operation_name": operation.name,
                "graphql_operation_type": operation.operation_type.value,
                "graphql_return_type": operation.type_ref.display(),
                "graphql_arguments": argument_metadata,
                "graphql_source_format": schema.source_format,
                "graphql_schema_id": schema.schema_id,
                "graphql_discovery_only": True,
            },
        )

    def _types(self, schema: GraphQLSchema) -> list[TypeDefinition]:
        definitions: list[TypeDefinition] = []
        definitions.extend(self._object_type(type_definition, schema) for type_definition in schema.object_types)
        definitions.extend(self._input_object(input_object, schema) for input_object in schema.input_objects)
        definitions.extend(self._enum_type(enum) for enum in schema.enums)
        return definitions

    def _object_type(self, type_definition: GraphQLType, schema: GraphQLSchema) -> TypeDefinition:
        return TypeDefinition(
            name=type_definition.name,
            api_style=ApiStyle.GRAPHQL,
            field_type=FieldType.OBJECT,
            fields=[
                self._field_definition(field.name, field.type_ref, schema, field.description)
                for field in type_definition.fields
            ],
            description=type_definition.description,
            metadata={"graphql_type_kind": type_definition.kind.value},
        )

    def _input_object(self, input_object: GraphQLInputObject, schema: GraphQLSchema) -> TypeDefinition:
        return TypeDefinition(
            name=input_object.name,
            api_style=ApiStyle.GRAPHQL,
            field_type=FieldType.OBJECT,
            fields=[
                self._field_definition(field.name, field.type_ref, schema, field.description)
                for field in input_object.fields
            ],
            description=input_object.description,
            metadata={"graphql_type_kind": input_object.kind.value},
        )

    def _enum_type(self, enum: GraphQLEnum) -> TypeDefinition:
        return TypeDefinition(
            name=enum.name,
            api_style=ApiStyle.GRAPHQL,
            field_type=FieldType.ENUM,
            enum_values=enum.enum_values,
            description=enum.description,
            metadata={"graphql_type_kind": enum.kind.value},
        )

    def _field_definition(
        self,
        name: str,
        type_ref: GraphQLTypeRef,
        schema: GraphQLSchema,
        description: str | None,
    ) -> FieldDefinition:
        field_type = self._field_type(type_ref, schema)
        item_type = None
        if field_type == FieldType.ARRAY and type_ref.of_type is not None:
            inner = self._unwrap_non_null(type_ref.of_type)
            item_type = TypeReference(
                name=inner.named_type(),
                field_type=self._field_type(inner, schema),
            )
        return FieldDefinition(
            name=name,
            field_type=field_type,
            required=type_ref.is_non_null(),
            nullable=not type_ref.is_non_null(),
            array_item_type=item_type,
            description=description,
            constraints=self._constraints(type_ref, schema),
            metadata={"graphql_type": type_ref.display()},
        )

    def _constraints(self, type_ref: GraphQLTypeRef, schema: GraphQLSchema) -> list[Constraint]:
        named_type = type_ref.named_type()
        if named_type is None:
            return []
        enum_values = {
            enum.name: enum.enum_values
            for enum in schema.enums
        }.get(named_type)
        if enum_values is None:
            return []
        return [
            Constraint(
                constraint_type=ConstraintType.ENUM,
                value=enum_values,
                source="graphql_schema",
            )
        ]

    def _field_type(self, type_ref: GraphQLTypeRef, schema: GraphQLSchema) -> FieldType:
        unwrapped = self._unwrap_non_null(type_ref)
        if unwrapped.kind == GraphQLTypeKind.LIST:
            return FieldType.ARRAY
        name = unwrapped.named_type()
        if name in {enum.name for enum in schema.enums}:
            return FieldType.ENUM
        if name in {type_definition.name for type_definition in schema.object_types}:
            return FieldType.OBJECT
        if name in {input_object.name for input_object in schema.input_objects}:
            return FieldType.OBJECT
        return {
            "ID": FieldType.STRING,
            "String": FieldType.STRING,
            "Int": FieldType.INTEGER,
            "Float": FieldType.FLOAT,
            "Boolean": FieldType.BOOLEAN,
        }.get(name or "", FieldType.UNKNOWN)

    def _unwrap_non_null(self, type_ref: GraphQLTypeRef) -> GraphQLTypeRef:
        if type_ref.kind == GraphQLTypeKind.NON_NULL and type_ref.of_type is not None:
            return type_ref.of_type
        return type_ref

    def _argument_metadata(self, argument: GraphQLArgument) -> dict[str, object]:
        return {
            "name": argument.name,
            "type": argument.type_ref.display(),
            "required": argument.type_ref.is_non_null(),
            "default_value": argument.default_value,
        }

    def _stable_schema_hash(self, schema: GraphQLSchema) -> str:
        operation_text = "\n".join(
            f"{operation.operation_type.value}:{operation.name}:{operation.type_ref.display()}"
            for operation in schema.operations
        )
        return sha256(operation_text.encode("utf-8")).hexdigest()
