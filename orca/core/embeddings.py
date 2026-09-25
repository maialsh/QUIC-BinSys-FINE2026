"""
ORCA Embedding-Based Function Similarity Search

Generates embeddings for decompiled functions and enables:
  - Similar function lookup across binaries (cross-binary search)
  - Known malware function matching
  - Vulnerability pattern detection (similar to known CVE functions)
  - Function clustering by semantic similarity

Supports multiple embedding backends:
  - OpenAI text-embedding-3-small/large
  - Local sentence-transformers (offline)
  - LiteLLM proxy to any provider
"""
from __future__ import annotations
import hashlib, json, os, pickle, time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from dataclasses import dataclass, field


@dataclass
class FunctionEmbedding:
    """An embedded function with metadata."""
    binary_name: str
    function_name: str
    address: str
    decompiled_code: str
    embedding: np.ndarray
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def code_hash(self) -> str:
        return hashlib.sha256(self.decompiled_code.encode()).hexdigest()[:16]


@dataclass
class SimilarityResult:
    """A similarity search result."""
    function: FunctionEmbedding
    score: float  # cosine similarity, 0-1
    distance: float  # 1 - score


class EmbeddingProvider:
    """Generate embeddings using configurable backends."""

    def __init__(self, backend: str = "openai", model: Optional[str] = None):
        self.backend = backend
        self.model = model or self._default_model(backend)
        self._local_model = None

    def embed(self, texts: List[str]) -> np.ndarray:
        """Generate embeddings for a list of texts."""
        if self.backend == "openai":
            return self._embed_openai(texts)
        elif self.backend == "local":
            return self._embed_local(texts)
        elif self.backend == "litellm":
            return self._embed_litellm(texts)
        else:
            raise ValueError(f"Unknown embedding backend: {self.backend}")

    def embed_single(self, text: str) -> np.ndarray:
        return self.embed([text])[0]

    def _embed_openai(self, texts: List[str]) -> np.ndarray:
        try:
            from openai import OpenAI
            client = OpenAI()
            # Batch in chunks of 100
            all_embeddings = []
            for i in range(0, len(texts), 100):
                batch = texts[i:i+100]
                resp = client.embeddings.create(input=batch, model=self.model)
                all_embeddings.extend([d.embedding for d in resp.data])
            return np.array(all_embeddings, dtype=np.float32)
        except ImportError:
            raise RuntimeError("pip install openai")

    def _embed_local(self, texts: List[str]) -> np.ndarray:
        try:
            if self._local_model is None:
                from sentence_transformers import SentenceTransformer
                self._local_model = SentenceTransformer(self.model)
            return self._local_model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        except ImportError:
            raise RuntimeError("pip install sentence-transformers")

    def _embed_litellm(self, texts: List[str]) -> np.ndarray:
        try:
            import litellm
            all_embeddings = []
            for i in range(0, len(texts), 50):
                batch = texts[i:i+50]
                resp = litellm.embedding(model=self.model, input=batch)
                all_embeddings.extend([d["embedding"] for d in resp.data])
            return np.array(all_embeddings, dtype=np.float32)
        except ImportError:
            raise RuntimeError("pip install litellm")

    @staticmethod
    def _default_model(backend: str) -> str:
        return {
            "openai": "text-embedding-3-small",
            "local": "all-MiniLM-L6-v2",
            "litellm": "text-embedding-3-small",
        }.get(backend, "text-embedding-3-small")


class FunctionSimilarityIndex:
    """
    Vector index for function similarity search.

    Stores embeddings in-memory with optional disk persistence.
    Uses cosine similarity for matching.
    """

    def __init__(
        self,
        provider: Optional[EmbeddingProvider] = None,
        index_path: Optional[str] = None,
    ):
        self.provider = provider or EmbeddingProvider()
        self.functions: List[FunctionEmbedding] = []
        self._matrix: Optional[np.ndarray] = None  # stacked embeddings for fast search
        self._dirty = False
        self.index_path = Path(index_path) if index_path else None

        if self.index_path and self.index_path.exists():
            self._load()

    def add_function(
        self,
        binary_name: str,
        function_name: str,
        address: str,
        decompiled_code: str,
        metadata: Optional[Dict] = None,
    ) -> FunctionEmbedding:
        """Embed and index a single function."""
        embedding = self.provider.embed_single(self._prepare_code(decompiled_code))
        fe = FunctionEmbedding(
            binary_name=binary_name,
            function_name=function_name,
            address=address,
            decompiled_code=decompiled_code,
            embedding=embedding,
            metadata=metadata or {},
        )
        self.functions.append(fe)
        self._dirty = True
        self._matrix = None  # invalidate cache
        return fe

    def add_functions_batch(
        self,
        binary_name: str,
        functions: List[Dict[str, Any]],
    ) -> int:
        """
        Embed and index multiple functions at once (batched API call).

        Each dict in functions must have: name, address, decompiled_code
        Optional: metadata
        """
        if not functions:
            return 0

        texts = [self._prepare_code(f["decompiled_code"]) for f in functions]
        embeddings = self.provider.embed(texts)

        for i, f in enumerate(functions):
            fe = FunctionEmbedding(
                binary_name=binary_name,
                function_name=f["name"],
                address=f["address"],
                decompiled_code=f["decompiled_code"],
                embedding=embeddings[i],
                metadata=f.get("metadata", {}),
            )
            self.functions.append(fe)

        self._dirty = True
        self._matrix = None
        return len(functions)

    def search(
        self,
        query_code: str,
        top_k: int = 10,
        min_score: float = 0.0,
        exclude_binary: Optional[str] = None,
    ) -> List[SimilarityResult]:
        """Find functions most similar to the query code."""
        if not self.functions:
            return []

        query_embedding = self.provider.embed_single(self._prepare_code(query_code))
        return self.search_by_embedding(query_embedding, top_k, min_score, exclude_binary)

    def search_by_embedding(
        self,
        query_embedding: np.ndarray,
        top_k: int = 10,
        min_score: float = 0.0,
        exclude_binary: Optional[str] = None,
    ) -> List[SimilarityResult]:
        """Search using a pre-computed embedding vector."""
        if not self.functions:
            return []

        matrix = self._get_matrix()
        scores = self._cosine_similarity(query_embedding, matrix)

        # Filter and sort
        results = []
        for idx in np.argsort(scores)[::-1]:
            fe = self.functions[idx]
            score = float(scores[idx])

            if exclude_binary and fe.binary_name == exclude_binary:
                continue
            if score < min_score:
                break

            results.append(SimilarityResult(function=fe, score=score, distance=1 - score))
            if len(results) >= top_k:
                break

        return results

    def find_cross_binary_matches(
        self,
        binary_name: str,
        min_score: float = 0.85,
        top_k_per_function: int = 3,
    ) -> List[Dict[str, Any]]:
        """Find similar functions in other indexed binaries."""
        matches = []
        for fe in self.functions:
            if fe.binary_name != binary_name:
                continue
            results = self.search_by_embedding(
                fe.embedding,
                top_k=top_k_per_function + 1,
                min_score=min_score,
                exclude_binary=binary_name,
            )
            if results:
                matches.append({
                    "source_function": fe.function_name,
                    "source_address": fe.address,
                    "similar_functions": [
                        {
                            "binary": r.function.binary_name,
                            "function": r.function.function_name,
                            "address": r.function.address,
                            "score": round(r.score, 4),
                        }
                        for r in results
                    ],
                })
        return matches

    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics."""
        binaries = set(f.binary_name for f in self.functions)
        return {
            "total_functions": len(self.functions),
            "total_binaries": len(binaries),
            "binaries": list(binaries),
            "embedding_dim": self.functions[0].embedding.shape[0] if self.functions else 0,
        }

    def save(self):
        """Persist index to disk."""
        if self.index_path and self._dirty:
            self.index_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.index_path, "wb") as f:
                pickle.dump(self.functions, f)
            self._dirty = False

    def _load(self):
        try:
            with open(self.index_path, "rb") as f:
                self.functions = pickle.load(f)
            self._matrix = None
        except Exception:
            self.functions = []

    def _get_matrix(self) -> np.ndarray:
        if self._matrix is None:
            self._matrix = np.stack([f.embedding for f in self.functions])
        return self._matrix

    @staticmethod
    def _cosine_similarity(query: np.ndarray, matrix: np.ndarray) -> np.ndarray:
        query_norm = query / (np.linalg.norm(query) + 1e-10)
        matrix_norm = matrix / (np.linalg.norm(matrix, axis=1, keepdims=True) + 1e-10)
        return matrix_norm @ query_norm

    @staticmethod
    def _prepare_code(code: str) -> str:
        """Prepare decompiled code for embedding (strip noise, normalise)."""
        lines = code.strip().split("\n")
        # Remove empty lines and very short comment-only lines
        cleaned = []
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("//"):
                cleaned.append(stripped)
        return "\n".join(cleaned[:100])  # cap at 100 lines for embedding
