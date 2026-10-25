from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field, model_validator

from vesper.config import StrictModel

if TYPE_CHECKING:
    from vesper.app import Application

Identifier = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9_.-]+$")]
ClassName = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z_$][A-Za-z0-9_.$]*$")]
Selector = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z_][A-Za-z0-9_:]*$")]


class Empty(StrictModel):
    pass


class DeviceRequest(StrictModel):
    device_id: Identifier


class AppRequest(DeviceRequest):
    bundle_id: Identifier


class SessionRequest(DeviceRequest):
    session_id: Identifier


class TargetRequest(DeviceRequest):
    bundle_id: Identifier | None = None
    session_id: Identifier | None = None

    @model_validator(mode="after")
    def target(self) -> TargetRequest:
        if (self.bundle_id is None) == (self.session_id is None):
            raise ValueError("Choose bundle_id or an existing session_id")
        return self


async def resolve_target(app: Application, request: TargetRequest) -> dict[str, Any]:
    app.permissions.device(request.device_id, request.bundle_id)
    if request.session_id is not None:
        session = app.frida.session(request.device_id, request.session_id)
        return {**session.metadata(), "reused": True}
    assert request.bundle_id is not None
    return await app.frida.attach(request.device_id, request.bundle_id)


class Page(StrictModel):
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=100, ge=1, le=500)


class SessionPage(SessionRequest, Page):
    pass


class ClassRequest(SessionRequest):
    class_name: ClassName


class MethodRequest(ClassRequest):
    selector: Selector
    class_method: bool = False


class JobRequest(StrictModel):
    job_id: Identifier
