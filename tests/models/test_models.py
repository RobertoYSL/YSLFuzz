from yslfuzz.models import (
    ApiSchema,
    ApiStyle,
    AttackCategory,
    AuthScheme,
    AuthType,
    Constraint,
    ConstraintType,
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    DetectorResult,
    Endpoint,
    Evidence,
    ExecutionPlan,
    ExecutionResult,
    ExecutionStatus,
    FieldDefinition,
    FieldType,
    FindingConfidence,
    FindingSeverity,
    GeneratedParameter,
    HttpMethod,
    Parameter,
    ParameterLocation,
    PayloadCandidate,
    PayloadKind,
    Project,
    Protocol,
    Report,
    ReportSummary,
    RequestBodyDefinition,
    RequestRecord,
    ResponseDefinition,
    ResponseRecord,
    ScanConfiguration,
    ScanMetrics,
    ScanRun,
    SchemaSource,
    ScopeDefinition,
    SecurityFinding,
    SessionState,
    Target,
    TypeDefinition,
    Workflow,
    WorkflowStep,
)


def test_create_all_mvp_models() -> None:
    scope = ScopeDefinition(allowed_hosts=["localhost"])
    config = ScanConfiguration(target_id="target_1")
    source = SchemaSource(source_type="OPENAPI_FILE", location="openapi.yaml", api_style=ApiStyle.REST)
    auth_scheme = AuthScheme(
        auth_type=AuthType.API_KEY,
        name="api_key",
        location=ParameterLocation.HEADER,
        header_name="X-API-Key",
    )
    constraint = Constraint(
        constraint_type=ConstraintType.MIN_LENGTH,
        value=1,
        source="openapi",
    )
    field = FieldDefinition(
        name="name",
        field_type=FieldType.STRING,
        required=True,
        constraints=[constraint],
    )
    type_definition = TypeDefinition(
        name="User",
        api_style=ApiStyle.REST,
        field_type=FieldType.OBJECT,
        fields=[field],
    )
    parameter = Parameter(
        name="id",
        location=ParameterLocation.PATH,
        field_type=FieldType.UUID,
        required=True,
    )
    request_body = RequestBodyDefinition(
        content_type="application/json",
        required=True,
        fields=[field],
    )
    response = ResponseDefinition(status_code=200, content_type="application/json", fields=[field])
    endpoint = Endpoint(
        api_schema_id="api_schema_1",
        name="get_user",
        api_style=ApiStyle.REST,
        path="/users/{id}",
        method=HttpMethod.GET,
        parameters=[parameter],
        request_body=request_body,
        responses=[response],
    )
    api_schema = ApiSchema(
        target_id="target_1",
        api_style=ApiStyle.REST,
        base_url="http://localhost:8000",
        endpoints=[endpoint],
        types=[type_definition],
        auth_schemes=[auth_scheme],
        created_from=[source],
    )
    target = Target(
        name="local",
        base_url="http://localhost:8000",
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTP,
        scope=scope,
        schema_sources=[source],
    )
    scan = ScanRun(
        project_id="project_1",
        target_id=target.target_id,
        scan_config_id=config.scan_config_id,
        api_schema_id=api_schema.api_schema_id,
    )
    project = Project(name="demo", targets=[target], scans=[scan])
    node = DependencyNode(node_type="ENDPOINT", ref_id=endpoint.endpoint_id, label="GET user")
    edge = DependencyEdge(
        source_node_id=node.node_id,
        target_node_id=node.node_id,
        dependency_type="CONSUMES",
    )
    workflow_step = WorkflowStep(endpoint_id=endpoint.endpoint_id, order=1)
    workflow = Workflow(name="read user", steps=[workflow_step])
    graph = DependencyGraph(api_schema_id=api_schema.api_schema_id, nodes=[node], edges=[edge])
    generated_parameter = GeneratedParameter(
        name="id",
        location=ParameterLocation.PATH,
        value="user_1",
        field_type=FieldType.STRING,
    )
    payload = PayloadCandidate(
        endpoint_id=endpoint.endpoint_id,
        payload_kind=PayloadKind.VALID,
        content_type="application/json",
        parameters=[generated_parameter],
        generation_strategy="unit-test",
        seed=1,
    )
    plan = ExecutionPlan(scan_run_id=scan.scan_run_id, workflows=[workflow], standalone_payloads=[payload])
    session = SessionState(headers={"Accept": "application/json"})
    request = RequestRecord(
        scan_run_id=scan.scan_run_id,
        endpoint_id=endpoint.endpoint_id,
        payload_id=payload.payload_id,
        method=HttpMethod.GET,
        url="http://localhost:8000/users/user_1",
    )
    response_record = ResponseRecord(request_id=request.request_id, status_code=200)
    result = ExecutionResult(
        request_id=request.request_id,
        response_id=response_record.response_id,
        status=ExecutionStatus.COMPLETED,
    )
    evidence = Evidence(
        evidence_type="status",
        source="response",
        description="Observed expected response",
        request_id=request.request_id,
        response_id=response_record.response_id,
    )
    detector_result = DetectorResult(
        detector_id="detector_1",
        request_id=request.request_id,
        response_id=response_record.response_id,
        matched=True,
        evidence=[evidence],
    )
    finding = SecurityFinding(
        scan_run_id=scan.scan_run_id,
        endpoint_id=endpoint.endpoint_id,
        title="Information disclosure",
        description="Test finding",
        attack_category=AttackCategory.INFORMATION_DISCLOSURE,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.LOW,
        request_ids=[request.request_id],
        response_ids=[response_record.response_id],
        evidence=[evidence],
    )
    metrics = ScanMetrics(scan_run_id=scan.scan_run_id, total_endpoints=1, tested_endpoints=1)
    report = Report(
        scan_run_id=scan.scan_run_id,
        summary=ReportSummary(),
        findings=[finding],
        metrics=metrics,
    )

    assert project.targets == [target]
    assert graph.nodes == [node]
    assert plan.standalone_payloads == [payload]
    assert session.headers == {"Accept": "application/json"}
    assert result.status == ExecutionStatus.COMPLETED
    assert detector_result.matched is True
    assert report.metrics.scan_run_id == scan.scan_run_id
