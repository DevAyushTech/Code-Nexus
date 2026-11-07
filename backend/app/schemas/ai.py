from pydantic import BaseModel, ConfigDict, Field


class ScamAIResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scam_indicators: list[str] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)
    extracted_emails: list[str] = Field(default_factory=list)
    extracted_phone_numbers: list[str] = Field(default_factory=list)
    explanation: str = Field(min_length=1, max_length=4_000)
    recommendations: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
