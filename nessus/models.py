from typing import Any

from pydantic import BaseModel, model_serializer


class ScanFiltersItem(BaseModel):
    filter: str
    quality: str
    value: Any


class ScanFilters(BaseModel):
    search_type: str
    filters: list[ScanFiltersItem]

    @model_serializer
    def serialize(self):
        data = {"search_type": self.search_type}

        for index, item in enumerate(self.filters):
            prefix = f"filter.{index}"

            data[f"{prefix}.filter"] = item.filter
            data[f"{prefix}.quality"] = item.quality
            data[f"{prefix}.value"] = item.value

        return data


class ScanCreateSettings(BaseModel):
    """Not complete, only the necessary settings."""

    name: str
    text_targets: str
    description: str = None

    enabled: bool = True

    policy_id: int = None
    folder_id: int = None
