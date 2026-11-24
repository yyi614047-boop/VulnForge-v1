"""Built-in, deterministic File Write verification profiles."""
from __future__ import annotations

from dataclasses import dataclass

from app.verification.models import FileArtifactExpectation


@dataclass(frozen=True)
class FileWriteProfile:
    options: dict[str, str]
    expectation: FileArtifactExpectation


FILE_WRITE_PROFILES = {
    "exploit/multi/http/apache_activemq_upload_jsp": FileWriteProfile(
        options={"JSP": "vulnforge_probe", "UploadPath": "api", "AutoCleanup": "false"},
        expectation=FileArtifactExpectation(
            path_pattern="/opt/*/webapps/api/vulnforge_probe.jsp",
            source="builtin:apache_activemq_upload_jsp",
        ),
    ),
}


def file_write_profile(module_name: str) -> FileWriteProfile | None:
    return FILE_WRITE_PROFILES.get(module_name)
