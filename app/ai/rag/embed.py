from google import genai
from google.genai import types
from app.core.config import settings

class Embedder:
    def __init__(self):
        self.client = genai.Client(api_key=settings.gemini_api_key)

    def embed(self, text: str, task_type="RETRIEVAL_DOCUMENT") -> list[float]:
        response = self.client.models.embed_content(
            model=settings.gemini_embedding_model,
            contents=text,
            config=types.EmbedContentConfig(task_type=task_type, output_dimensionality=settings.embedding_dimension),
        )
        if not response.embeddings or not response.embeddings[0].values:
            raise RuntimeError("Gemini returned an empty embedding.")
        return list(response.embeddings[0].values)

    def embed_batch(self, texts: list[str], task_type="RETRIEVAL_DOCUMENT") -> list[list[float]]:
        """
        Embed multiple texts in a single Gemini API call.
        Returns a list of embedding vectors corresponding 1:1 to input texts.
        """
        if not texts:
            return []
        response = self.client.models.embed_content(
            model=settings.gemini_embedding_model,
            contents=texts,
            config=types.EmbedContentConfig(task_type=task_type, output_dimensionality=settings.embedding_dimension),
        )
        if not response.embeddings or len(response.embeddings) != len(texts):
            actual_count = len(response.embeddings) if response.embeddings else 0
            raise RuntimeError(f"Expected {len(texts)} embeddings from Gemini, got {actual_count}")
        return [list(emb.values) for emb in response.embeddings]
