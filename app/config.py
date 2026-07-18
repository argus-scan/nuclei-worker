from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    nats_url: str = "nats://localhost:4222"
    port: int = 8008
