"""Catalog models: scan modules and scan profiles."""

from api.models.results import ScanCategory
from pydantic import BaseModel, Field


class ModuleInfo(BaseModel):
    """A scanning module that can be requested in a full scan."""

    id: str = Field(..., description="Module identifier used in ScanRequest.modules")
    name: str = Field(..., description="Human-readable module name")
    description: str = Field(..., description="What the module checks")
    category: ScanCategory = Field(..., description="Category of the module")
    intrusive: bool = Field(
        ..., description="Whether the module submits forms or payloads to the target"
    )
    default_timeout: int = Field(..., ge=1, description="Suggested timeout in seconds")


class ScanProfile(BaseModel):
    """A named, ordered set of modules."""

    id: str = Field(..., description="Profile identifier used in ScanRequest.profile")
    name: str = Field(..., description="Human-readable profile name")
    description: str = Field(..., description="What the profile covers")
    modules: list[str] = Field(..., description="Modules run by this profile, in order")


class Catalog(BaseModel):
    """Modules and profiles available on this instance."""

    modules: list[ModuleInfo]
    profiles: list[ScanProfile]
    default_profile: str
