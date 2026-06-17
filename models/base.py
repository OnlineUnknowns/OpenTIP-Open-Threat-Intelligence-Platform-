from sqlmodel import SQLModel

# Re-exporting SQLModel and shared metadata
# This allows all schemas to share a single metadata registry
metadata = SQLModel.metadata
