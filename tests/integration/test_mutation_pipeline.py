from pathlib import Path

from yslfuzz.discovery import OpenAPIParser
from yslfuzz.models import PayloadKind
from yslfuzz.payloads import MutationConfig, MutationEngine, PayloadGenerator


def test_mutation_pipeline_from_openapi_payload_is_deterministic_and_local(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network call attempted")

    monkeypatch.setattr("socket.create_connection", fail_network_call)
    api_schema = OpenAPIParser().parse(Path("examples/openapi/simple_users_api.yaml"))
    endpoint = next(endpoint for endpoint in api_schema.endpoints if endpoint.name == "createUser")
    payload = PayloadGenerator(seed=3).generate_for_endpoint(endpoint)
    config = MutationConfig(max_mutations_per_payload=10, max_mutations_per_field=2, random_seed=5)

    first = MutationEngine(config).mutate(endpoint, payload)
    second = MutationEngine(config).mutate(endpoint, payload)

    assert first
    assert [mutation.payload_kind for mutation in first] == [mutation.payload_kind for mutation in second]
    assert [mutation.metadata["mutation_name"] for mutation in first] == [
        mutation.metadata["mutation_name"] for mutation in second
    ]
    assert {mutation.payload_kind for mutation in first} <= {
        PayloadKind.BOUNDARY,
        PayloadKind.INVALID,
        PayloadKind.MUTATED,
    }
