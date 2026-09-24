"""Input normalization service — offline security preprocessing.

Does not call LLMs, does not decide ALLOW/BLOCK, does not persist content.
"""

from __future__ import annotations

from app.core.config import Settings, get_settings
from app.core.enums import SourceType
from app.security.chunking import TextChunker
from app.security.control_chars import analyze_control_characters
from app.security.encoding import analyze_encodings
from app.security.errors import PreprocessingError
from app.security.html_analysis import analyze_html
from app.security.prompt_markers import analyze_prompt_boundaries
from app.security.types import SecurityInput
from app.security.unicode_analysis import analyze_unicode, normalize_unicode_nfkc
from app.security.whitespace import normalize_whitespace


class InputNormalizationService:
    """Validate and normalize untrusted text into a ``SecurityInput``."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.chunker = TextChunker(
            max_units=self.settings.max_chunk_length,
            overlap_units=self.settings.chunk_overlap_length,
            max_chunks=self.settings.max_chunks,
        )

    def normalize(self, content: str, source_type: SourceType) -> SecurityInput:
        """Run the preprocessing pipeline. Raises on empty / oversized input."""
        if content is None or not isinstance(content, str):
            raise PreprocessingError(
                "INVALID_INPUT",
                "content must be a non-empty string",
            )
        if not content.strip():
            raise PreprocessingError(
                "EMPTY_CONTENT",
                "content must not be empty or whitespace-only",
            )
        if len(content) > self.settings.max_input_length:
            raise PreprocessingError(
                "INPUT_TOO_LARGE",
                f"content exceeds MAX_INPUT_LENGTH ({self.settings.max_input_length})",
            )

        preprocessing_errors: list[str] = []

        unicode_flags = analyze_unicode(content)
        control_flags = analyze_control_characters(content)

        # Normalize for detection: NFKC then whitespace (preserve evidence via flags)
        nfkc = normalize_unicode_nfkc(content)
        normalized = normalize_whitespace(nfkc)

        encoding_flags, derived, enc_errors = analyze_encodings(
            content,
            max_decoded_length=self.settings.max_decoded_length,
            max_decode_depth=self.settings.max_decode_depth,
            max_encoded_candidates=self.settings.max_encoded_candidates,
        )
        preprocessing_errors.extend(enc_errors)

        # Also scan normalized text for markers/HTML (structure on readable form)
        html_flags = analyze_html(normalized)
        # Merge HTML signals from original if comments only in raw
        raw_html = analyze_html(content)
        structure_from_html = {
            "html_detected": html_flags["html_detected"] or raw_html["html_detected"],
            "html_comment_detected": (
                html_flags["html_comment_detected"] or raw_html["html_comment_detected"]
            ),
            "html_comment_count": max(
                html_flags["html_comment_count"], raw_html["html_comment_count"]
            ),
            "hidden_content_detected": (
                html_flags["hidden_content_detected"]
                or raw_html["hidden_content_detected"]
            ),
            "script_detected": html_flags["script_detected"] or raw_html["script_detected"],
            "script_tag_count": max(
                html_flags["script_tag_count"], raw_html["script_tag_count"]
            ),
            "iframe_detected": html_flags["iframe_detected"] or raw_html["iframe_detected"],
            "iframe_tag_count": max(
                html_flags["iframe_tag_count"], raw_html["iframe_tag_count"]
            ),
        }

        boundary_flags = analyze_prompt_boundaries(normalized)
        raw_boundary = analyze_prompt_boundaries(content)
        structure_flags = {
            **structure_from_html,
            "instruction_boundary_detected": (
                boundary_flags["instruction_boundary_detected"]
                or raw_boundary["instruction_boundary_detected"]
            ),
            "role_marker_detected": (
                boundary_flags["role_marker_detected"]
                or raw_boundary["role_marker_detected"]
            ),
            "tool_marker_detected": (
                boundary_flags["tool_marker_detected"]
                or raw_boundary["tool_marker_detected"]
            ),
            "xml_instruction_block_detected": (
                boundary_flags["xml_instruction_block_detected"]
                or raw_boundary["xml_instruction_block_detected"]
            ),
            "markdown_instruction_section_detected": (
                boundary_flags["markdown_instruction_section_detected"]
                or raw_boundary["markdown_instruction_section_detected"]
            ),
        }

        obfuscation_flags = {
            "possible_obfuscation": any(
                [
                    unicode_flags.get("zero_width_detected"),
                    unicode_flags.get("bidi_control_detected"),
                    encoding_flags.get("base64_candidate"),
                    encoding_flags.get("url_encoding_detected"),
                    encoding_flags.get("unicode_escape_detected"),
                    encoding_flags.get("hex_candidate"),
                    structure_from_html.get("hidden_content_detected"),
                ]
            ),
            "derived_representation_count": len(derived),
            # Length only — never include derived plaintext in flags/logs
            "derived_total_chars": sum(len(d) for d in derived),
        }

        # Detection text: normalized primary, optionally append bounded derived
        # segments separated clearly (derived already size-limited).
        detection_text = normalized
        if derived:
            appendix = "\n".join(derived)
            remaining = self.settings.max_decoded_length
            if remaining > 0:
                detection_text = f"{normalized}\n\n{appendix[:remaining]}"

        chunks = self.chunker.chunk_text(detection_text)
        chunk_truncated = (
            len(detection_text) > self.settings.max_chunk_length
            and len(chunks) >= self.settings.max_chunks
            and (chunks[-1].end_offset < len(detection_text) if chunks else False)
        )
        if chunk_truncated:
            preprocessing_errors.append("chunk_limit_reached")

        normalization_flags = {
            **unicode_flags,
            **control_flags,
            "whitespace_normalized": normalized != nfkc or nfkc != content,
            "nfkc_applied": nfkc != content,
        }

        metadata = {
            "source_type": source_type.value,
            "chunk_count": len(chunks),
            "chunk_truncated": chunk_truncated,
            "tokenizer": "character_fallback",
            "tokenizer_note": (
                "Chunk sizes use character units, not Prompt Guard token counts."
            ),
            "max_chunk_length": self.settings.max_chunk_length,
            "chunk_overlap_length": self.settings.chunk_overlap_length,
            "verdict": None,
            "note": (
                "Normalization and preprocessing do not determine whether an "
                "input is malicious."
            ),
        }

        return SecurityInput(
            original_length=len(content),
            normalized_length=len(normalized),
            normalized_text=normalized,
            normalization_flags=normalization_flags,
            encoding_flags=encoding_flags,
            structure_flags=structure_flags,
            obfuscation_flags=obfuscation_flags,
            chunks=chunks,
            metadata=metadata,
            preprocessing_errors=preprocessing_errors,
            source_type=source_type,
        )
