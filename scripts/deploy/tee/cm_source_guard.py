#!/usr/bin/env python3
"""CM server.rs 的构建前分派守卫。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Iterable


EXPECTED_METHODS = (
    "get_ra_cert",
    "create_data_keys",
    "get_data_keys",
    "delete_data_key",
    "get_export_data_key",
    "register_cert",
    "create_data_policy",
    "list_data_policy",
    "add_data_rule",
    "delete_data_policy",
    "delete_data_rule",
    "create_result_data_key",
)


class SourceSyntaxError(ValueError):
    """源文件无法按本守卫支持的 Rust 语法安全解析。"""


@dataclass(frozen=True)
class Token:
    kind: str
    text: str


def _skip_quoted(source: str, start: int, quote: str) -> int:
    index = start + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == quote:
            return index + 1
        if source[index] in "\r\n" and quote == "'":
            raise SourceSyntaxError("未闭合字符字面量")
        index += 1
    raise SourceSyntaxError("未闭合字符串或字符字面量")


def _skip_raw_string(source: str, start: int) -> int | None:
    """跳过 r#"..."#、br#"..."# 等 Rust 原始字面量。"""
    prefix_end = start
    if source.startswith("br", start):
        prefix_end += 2
    elif source.startswith("r", start):
        prefix_end += 1
    else:
        return None

    hash_count = 0
    while prefix_end + hash_count < len(source) and source[prefix_end + hash_count] == "#":
        hash_count += 1
    quote_index = prefix_end + hash_count
    if quote_index >= len(source) or source[quote_index] != '"':
        return None

    terminator = '"' + ("#" * hash_count)
    end = source.find(terminator, quote_index + 1)
    if end < 0:
        raise SourceSyntaxError("未闭合原始字符串字面量")
    return end + len(terminator)


def _tokenize(source: str) -> list[Token]:
    """去除注释和字面量后生成有限的 Rust 词法令牌。"""
    tokens: list[Token] = []
    index = 0
    while index < len(source):
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            depth = 1
            index += 2
            while index < len(source) and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise SourceSyntaxError("未闭合块注释")
            continue

        raw_end = _skip_raw_string(source, index)
        if raw_end is not None:
            tokens.append(Token("literal", source[index:raw_end]))
            index = raw_end
            continue
        if char in "\"":
            end = _skip_quoted(source, index, char)
            tokens.append(Token("literal", source[index:end]))
            index = end
            continue
        if char == "'" and index + 2 < len(source):
            # 仅把形如 'a' 或 '\\n' 的内容视为字符字面量，保留 Rust 生命周期令牌。
            if source[index + 2] == "'" or source[index + 1] == "\\":
                end = _skip_quoted(source, index, char)
                tokens.append(Token("literal", source[index:end]))
                index = end
                continue

        if char.isalpha() or char == "_":
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] == "_"):
                end += 1
            tokens.append(Token("ident", source[index:end]))
            index = end
            continue

        tokens.append(Token("punct", char))
        index += 1

    return tokens


def _matching_delimiters(tokens: list[Token]) -> dict[int, int]:
    pairs = {"(": ")", "[": "]", "{": "}"}
    closing = set(pairs.values())
    stack: list[tuple[str, int]] = []
    matches: dict[int, int] = {}
    for index, token in enumerate(tokens):
        if token.text in pairs:
            stack.append((token.text, index))
        elif token.text in closing:
            if not stack or pairs[stack[-1][0]] != token.text:
                raise SourceSyntaxError("分隔符不匹配")
            _, opening = stack.pop()
            matches[opening] = index
            matches[index] = opening
    if stack:
        raise SourceSyntaxError("分隔符未闭合")
    return matches


def _find_headers(tokens: list[Token], words: tuple[str, ...]) -> list[int]:
    return [
        index
        for index in range(len(tokens) - len(words) + 1)
        if tuple(token.text for token in tokens[index : index + len(words)]) == words
    ]


def _find_block_start(tokens: list[Token], start: int, end: int) -> int:
    paren = square = 0
    for index in range(start, end):
        text = tokens[index].text
        if text == "(":
            paren += 1
        elif text == ")":
            paren -= 1
        elif text == "[":
            square += 1
        elif text == "]":
            square -= 1
        elif text == "{" and paren == 0 and square == 0:
            return index
        elif text == ";" and paren == 0 and square == 0:
            raise SourceSyntaxError("接口或实现声明缺少代码块")
    raise SourceSyntaxError("接口或实现代码块缺失")


def _skip_attribute(tokens: list[Token], index: int, end: int, matches: dict[int, int]) -> int:
    if index >= end or tokens[index].text != "#":
        return index
    if index + 1 >= end or tokens[index + 1].text != "[":
        raise SourceSyntaxError("属性语法不完整")
    close = matches.get(index + 1)
    if close is None or close >= end:
        raise SourceSyntaxError("属性括号未闭合")
    return close + 1


def _parse_methods(
    tokens: list[Token],
    block_start: int,
    block_end: int,
    matches: dict[int, int],
    implementation: bool,
) -> tuple[list[str], list[str]]:
    names: list[str] = []
    errors: list[str] = []
    index = block_start + 1
    while index < block_end:
        next_index = _skip_attribute(tokens, index, block_end, matches)
        if next_index != index:
            index = next_index
            continue

        if index + 2 >= block_end or tokens[index].text != "async" or tokens[index + 1].text != "fn":
            errors.append("代码块中存在无法识别的顶层项")
            break
        name_token = tokens[index + 2]
        if name_token.kind != "ident":
            errors.append("async fn 缺少合法接口名")
            break
        name = name_token.text
        names.append(name)
        if index + 3 >= block_end or tokens[index + 3].text != "(":
            errors.append(f"{name}: 方法参数列表缺失")
            break
        close_params = matches.get(index + 3)
        if close_params is None or close_params >= block_end:
            errors.append(f"{name}: 方法参数列表未闭合")
            break

        boundary = close_params + 1
        paren = square = 0
        while boundary < block_end:
            text = tokens[boundary].text
            if text == "(":
                paren += 1
            elif text == ")":
                paren -= 1
            elif text == "[":
                square += 1
            elif text == "]":
                square -= 1
            elif paren == 0 and square == 0 and text in (";", "{"):
                break
            boundary += 1
        if boundary >= block_end:
            errors.append(f"{name}: 方法签名未结束")
            break

        if implementation:
            if tokens[boundary].text != "{":
                errors.append(f"{name}: 实现方法缺少方法体")
                break
            body_end = matches.get(boundary)
            if body_end is None or body_end > block_end:
                errors.append(f"{name}: 方法体未闭合")
                break
            errors.extend(_validate_dispatch_body(tokens, name, boundary + 1, body_end))
            index = body_end + 1
        else:
            if tokens[boundary].text != ";":
                errors.append(f"{name}: trait 方法必须以分号结束")
                break
            index = boundary + 1

    return names, errors


def _validate_dispatch_body(tokens: list[Token], name: str, start: int, end: int) -> list[str]:
    body = [token.text for token in tokens[start:end]]
    expected = ["self", ".", f"{name}_impl", "(", "request", ")", ".", "await"]
    if name == "create_result_data_key":
        expected = ["self", ".", f"{name}_impl", "(", "&", "request", ")", ".", "await"]
    if body == expected:
        return []
    if "self" in body and "." in body and "await" in body:
        return [f"{name}: 分派必须唯一调用 self.{name}_impl(request).await"]
    return [f"{name}: 方法体必须只包含 self.{name}_impl(request).await"]


def _result(
    *,
    ok: bool,
    trait_methods: Iterable[str] = (),
    impl_methods: Iterable[str] = (),
    errors: Iterable[str] = (),
) -> dict[str, object]:
    trait = list(trait_methods)
    implementation = list(impl_methods)
    error_list = list(errors)
    return {
        "ok": ok and not error_list,
        "interface_names": trait,
        "interface_count": len(trait),
        "trait_methods": trait,
        "trait_method_count": len(trait),
        "impl_methods": implementation,
        "impl_method_count": len(implementation),
        "errors": error_list,
    }


def validate_dispatch(source_text: str) -> dict[str, object]:
    """验证 CM trait 与 impl 的完整分派关系，任何不确定情况均拒绝。"""
    if not isinstance(source_text, str):
        return _result(ok=False, errors=["源文本必须是字符串"])

    try:
        tokens = _tokenize(source_text)
        matches = _matching_delimiters(tokens)
        trait_headers = _find_headers(tokens, ("trait", "CapsuleManagerService"))
        impl_headers = _find_headers(
            tokens,
            ("impl", "CapsuleManagerService", "for", "CapsuleManagerImpl"),
        )
        errors: list[str] = []
        if len(trait_headers) != 1:
            errors.append(f"CapsuleManagerService trait 数量应为 1，实际为 {len(trait_headers)}")
        if len(impl_headers) != 1:
            errors.append(f"CapsuleManagerService impl 数量应为 1，实际为 {len(impl_headers)}")
        if errors:
            return _result(ok=False, errors=errors)

        trait_start = _find_block_start(tokens, trait_headers[0] + 2, len(tokens))
        trait_end = matches.get(trait_start)
        impl_start = _find_block_start(tokens, impl_headers[0] + 4, len(tokens))
        impl_end = matches.get(impl_start)
        if trait_end is None or impl_end is None:
            raise SourceSyntaxError("trait 或 impl 代码块未闭合")

        trait_methods, trait_errors = _parse_methods(
            tokens, trait_start, trait_end, matches, implementation=False
        )
        impl_methods, impl_errors = _parse_methods(
            tokens, impl_start, impl_end, matches, implementation=True
        )
        errors = trait_errors + impl_errors
        if len(trait_methods) != len(set(trait_methods)):
            errors.append("trait 方法存在重复接口名")
        if len(impl_methods) != len(set(impl_methods)):
            errors.append("impl 方法存在重复接口名")
        expected = set(EXPECTED_METHODS)
        trait_set = set(trait_methods)
        impl_set = set(impl_methods)
        if trait_set != expected:
            errors.append("trait 接口名集合与固定 CM 契约不一致")
        if impl_set != expected:
            errors.append("impl 接口名集合与固定 CM 契约不一致")
        if set(trait_methods) != set(impl_methods):
            errors.append("trait 与 impl 方法集合不一致")
        return _result(
            ok=not errors,
            trait_methods=trait_methods,
            impl_methods=impl_methods,
            errors=errors,
        )
    except (SourceSyntaxError, IndexError, TypeError) as error:
        return _result(ok=False, errors=[f"解析失败并拒绝通过: {error}"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="验证 CM server.rs 的 trait 分派完整性")
    parser.add_argument("source_path", type=Path, help="待检查的 server.rs 路径")
    args = parser.parse_args(argv)
    try:
        source_text = args.source_path.read_text(encoding="utf-8")
        result = validate_dispatch(source_text)
    except (OSError, UnicodeError) as error:
        result = _result(ok=False, errors=[f"读取源文件失败并拒绝通过: {error}"])
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
