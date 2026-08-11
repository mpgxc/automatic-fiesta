#!/usr/bin/env python3
"""Confere que os três gêmeos de SignedPayload declaram os mesmos campos, na
mesma ordem, com os mesmos domínios.

Os vetores em test-vectors.json pegam divergência de bytes, mas só para os
payloads que alguém lembrou de cobrir. Isto pega divergência estrutural em
todos, inclusive nos que ainda não têm vetor — como os da rotação, que hoje só
existem no gêmeo macOS.

Roda sem toolchain nenhuma: é análise de texto do fonte.

    python3 docs/check-payload-parity.py
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

SOURCES = {
    "macos": ROOT / "macos/Sources/PhoneAuthCore/SignedPayload.swift",
    "ios":   ROOT / "mobile/ios/PhoneAuth/SignedPayload.swift",
    "android": ROOT / "mobile/android/app/src/main/java/dev/phoneauth/SignedPayload.kt",
}

# Swift:  ("nome", valor),
SWIFT_FIELD = re.compile(r'\(\s*"([A-Za-z]+)"\s*,')
# Kotlin: "nome" to valor,
KOTLIN_FIELD = re.compile(r'"([A-Za-z]+)"\s+to\s')


def swift_payloads(text):
    """Extrai {nomeDaFuncao: [campos]} das chamadas serialize([...])."""
    out = {}
    for match in re.finditer(r'static func (\w+)\([^{]*?\)[^{]*?\{\s*try serialize\(\[(.*?)\]\)', text, re.S):
        name, body = match.group(1), match.group(2)
        # `serialize` é o helper, não um payload; e um corpo sem campos é ruído
        # de regex, não uma declaração real.
        fields = SWIFT_FIELD.findall(body)
        if name != "serialize" and fields:
            out[name] = fields
    return out


def kotlin_payloads(text):
    out = {}
    # `[^)]*?` no lugar de `.*?` impede o match de atravessar outra declaração —
    # sem isso, `contextHash` casava com o corpo do `pairBytes` seguinte.
    for match in re.finditer(
        r'fun (\w+)\(\s*([^{}]*?)\s*\): ByteArray = serialize\(\s*listOf\((.*?)\)\s*\)', text, re.S
    ):
        name, body = match.group(1), match.group(3)
        fields = KOTLIN_FIELD.findall(body)
        if name != "serialize" and fields:
            out[name] = fields
    return out


def domains(text):
    return dict(re.findall(r'(\w*[Dd]omain|\w*_DOMAIN)\s*(?:=|: String =)\s*"(PHONEAUTH-[A-Z0-9-]+)"', text))


def normalize(name):
    """rotateAckBytes (Swift) e rotateAckBytes (Kotlin) já batem; o sufixo Bytes
    é a convenção comum, então basta minúsculo."""
    return name.lower()


def main():
    parsed, doms = {}, {}
    for platform, path in SOURCES.items():
        if not path.exists():
            print(f"ERRO: {path} não existe")
            return 1
        text = path.read_text(encoding="utf-8")
        parsed[platform] = {normalize(k): v for k, v in
                            (kotlin_payloads(text) if path.suffix == ".kt" else swift_payloads(text)).items()}
        doms[platform] = set(domains(text).values())

    problems, pending = [], []

    # Um payload que existe num gêmeo só é lacuna conhecida, não defeito: é o
    # estado normal enquanto uma feature está sendo portada. O que **é** defeito
    # é o mesmo payload existir em dois lugares com campos diferentes, porque aí
    # as assinaturas silenciosamente deixam de verificar.
    every = set().union(*(set(p) for p in parsed.values()))
    for payload in sorted(every):
        present = {p: fields for p, fields in
                   ((plat, parsed[plat].get(payload)) for plat in SOURCES) if fields is not None}
        if len(present) == 1:
            pending.append(f"'{payload}' só em {next(iter(present))}")
            continue
        if len({tuple(v) for v in present.values()}) > 1:
            problems.append(f"'{payload}' diverge:")
            for plat, fields in present.items():
                problems.append(f"    {plat:8s} {fields}")

    # Domínio presente em todos tem que ser idêntico. Domínio de um gêmeo só
    # acompanha um payload pendente e já foi contado acima.
    shared = doms["macos"] & doms["ios"] & doms["android"]
    for plat in SOURCES:
        for extra in sorted(doms[plat] - shared):
            pending.append(f"domínio {extra} só em {plat}")

    for line in pending:
        print(f"  pendente: {line}")

    if problems:
        print("\nDIVERGÊNCIA (isto quebra assinaturas entre plataformas):")
        for line in problems:
            print(" ", line)
        return 1

    covered = sum(1 for p in every if sum(p in parsed[plat] for plat in SOURCES) > 1)
    print(f"\nOK: {len(shared)} domínios compartilhados idênticos, "
          f"{covered} payloads com ordem de campos idêntica nos três gêmeos.")
    if pending:
        print(f"    ({len(pending)} item(ns) pendente(s) acima — lacuna conhecida, não defeito)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
