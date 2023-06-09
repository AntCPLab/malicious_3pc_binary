# Python Level

## Interfaces

| Interface | Usage |
| --------- | ----------- |
| `reveal` | ``res = a.clear_type(); asm_open(res, a)``|
| `Input int` | ``a = sint(); ldsi(a, int(12345678))``|
| `Input cint` | ``a = sint(); a.load_clear(a.clear_type(cint(12345678)))``|
| `Input from player` | ``a = sint(); asm_input(a, 0)``|
| `Get random bit share` | ``a = sint(); bit(a)``|
