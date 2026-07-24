from app.gateway_hunt.credential_validators.common import OpenAICompatibleValidator
from app.gateway_hunt.schemas import SecretArtifact
from urllib.parse import quote


class AzureOpenAIValidator(OpenAICompatibleValidator):
    provider = "azure_openai"
    auth_header = "api-key"
    auth_prefix = ""
    models_path = "/openai/models?api-version=2024-06-01"
    inference_path = "/openai/chat/completions?api-version=2024-06-01"

    def inference_path_for(self, artifact: SecretArtifact) -> str:
        deployment = artifact.validation_context.get("deployment")
        if not isinstance(deployment, str) or not deployment.strip():
            return self.inference_path
        encoded = quote(deployment.strip(), safe="")
        return (
            f"/openai/deployments/{encoded}/chat/completions"
            "?api-version=2024-06-01"
        )


__all__ = ["AzureOpenAIValidator"]
