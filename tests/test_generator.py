import string

import pytest

from vaultkey.generator import AMBIGUOUS_CHARACTERS, generate_password

TYPES = {
    "use_uppercase": string.ascii_uppercase,
    "use_lowercase": string.ascii_lowercase,
    "use_digits": string.digits,
    "use_symbols": string.punctuation,
}

COMBINATIONS = [
    {name: (name in chosen) for name in TYPES}
    for chosen in [
        set(TYPES),
        {"use_uppercase", "use_digits"},
        {"use_lowercase", "use_symbols", "use_digits"},
        {"use_digits"},
    ]
]


@pytest.mark.parametrize("options", COMBINATIONS)
@pytest.mark.parametrize("length", [4, 5, 8, 16])
@pytest.mark.parametrize("exclude_ambiguous", [False, True])
def test_every_selected_type_is_present(options, length, exclude_ambiguous):
    for _ in range(300):
        password = generate_password(length, exclude_ambiguous=exclude_ambiguous, **options)
        assert len(password) == length
        for name, chars in TYPES.items():
            present = any(c in chars for c in password)
            if options[name]:
                assert present, (password, name)
            else:
                assert not present, (password, name)
        if exclude_ambiguous:
            assert not set(password) & set(AMBIGUOUS_CHARACTERS)


def test_short_passwords_still_generate():
    assert len(generate_password(2)) == 2
    assert len(generate_password(1)) == 1


def test_output_is_not_trivially_repeated():
    assert len({generate_password(12) for _ in range(50)}) == 50


@pytest.mark.parametrize("kwargs", [
    {"length": 0},
    {"use_uppercase": False, "use_lowercase": False, "use_digits": False, "use_symbols": False},
])
def test_invalid_options_raise(kwargs):
    with pytest.raises(ValueError):
        generate_password(**kwargs)
