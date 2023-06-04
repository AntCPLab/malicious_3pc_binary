import itertools
from Compiler import types, library, instructions

def dest_comp(B):
    Bt = B.transpose()
    Bt_flat = Bt.get_vector()
    St_flat = Bt.value_type.Array(len(Bt_flat))
    St_flat.assign(Bt_flat)
    @library.for_range(len(St_flat) - 1)
    def _(i):
        St_flat[i + 1] = St_flat[i + 1] + St_flat[i]
    Tt_flat = Bt.get_vector() * St_flat.get_vector()
    Tt = types.Matrix(*Bt.sizes, B.value_type)
    Tt.assign_vector(Tt_flat)
    return sum(Tt) - 1

def reveal_sort(k, D, reverse=False):
    assert len(k) == len(D)
    library.break_point()
    shuffle = types.sint.get_secure_shuffle(len(k))
    k_prime = k.get_vector().secure_permute(shuffle).reveal()
    idx = types.Array.create_from(k_prime)
    if reverse:
        D.assign_vector(D.get_slice_vector(idx))
        library.break_point()
        D.secure_permute(shuffle, reverse=True)
    else:
        D.secure_permute(shuffle)
        library.break_point()
        v = D.get_vector()
        D.assign_slice_vector(idx, v)
    library.break_point()
    instructions.delshuffle(shuffle)

def radix_sort(k, D, n_bits=None, signed=True):
    assert len(k) == len(D)
    bs = types.Matrix.create_from(k.get_vector().bit_decompose(n_bits))
    if signed and len(bs) > 1:
        bs[-1][:] = bs[-1][:].bit_not()
    B = types.sint.Matrix(len(k), 2)
    h = types.Array.create_from(types.sint(types.regint.inc(len(k))))
    @library.for_range(len(bs))
    def _(i):
        b = bs[i]
        B.set_column(0, 1 - b.get_vector())
        B.set_column(1, b.get_vector())
        c = types.Array.create_from(dest_comp(B))
        reveal_sort(c, h, reverse=False)
        @library.if_e(i < len(bs) - 1)
        def _():
            reveal_sort(h, bs[i + 1], reverse=True)
        @library.else_
        def _():
            reveal_sort(h, D, reverse=True)
